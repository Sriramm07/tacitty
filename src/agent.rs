//! Per-user secret agent: holds the unlocked vault in memory behind a Unix
//! socket, so `tacitty shell` doesn't have to re-prompt for the master
//! passphrase on every alias lookup (spec §8.2).
//!
//! Wire protocol: length-prefixed frames, `u32` big-endian length + JSON
//! body. Kept intentionally tiny; there is no reason for this to be a real
//! RPC framework.

use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{self, Config};
use crate::secret::SecretBuf;
use crate::sys;
use crate::vault::{self, VaultData};

pub const MAX_FRAME: u32 = 1 << 20; // 1 MiB: generous, still bounded

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Protocol(String),
    #[error("vault is locked")]
    Locked,
    #[error("no secret stored for alias `{0}`")]
    NotFound(String),
    #[error("{0}")]
    Vault(#[from] vault::VaultError),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "UPPERCASE")]
pub enum Request {
    Get { alias: String },
    List,
    Lock,
    Status,
    Unlock { passphrase: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "ok")]
pub enum Response {
    #[serde(rename = "true")]
    Ok { data: ResponseData },
    #[serde(rename = "false")]
    Err { message: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseData {
    Secret {
        value: String,
    },
    Aliases {
        aliases: Vec<String>,
    },
    Status {
        unlocked: bool,
        idle_seconds: Option<u64>,
    },
    None {},
}

fn write_frame<W: Write>(w: &mut W, body: &[u8]) -> std::io::Result<()> {
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(body)?;
    w.flush()
}

fn read_frame<R: Read>(r: &mut R) -> Result<Vec<u8>, AgentError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(AgentError::Protocol("frame too large".into()));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    Ok(body)
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub struct Client {
    stream: UnixStream,
}

impl Client {
    pub fn connect(sock_path: &Path) -> Result<Self, AgentError> {
        let stream = UnixStream::connect(sock_path)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        // Verify we're actually talking to a process running as us before
        // sending anything, including the master passphrase.
        let peer = sys::peer_uid(std::os::fd::AsRawFd::as_raw_fd(&stream))?;
        if peer != sys::geteuid() {
            return Err(AgentError::Protocol(format!(
                "refusing to talk to agent socket owned by uid {peer}"
            )));
        }
        Ok(Client { stream })
    }

    fn call(&mut self, req: &Request) -> Result<Response, AgentError> {
        let body = serde_json::to_vec(req).map_err(|e| AgentError::Protocol(e.to_string()))?;
        write_frame(&mut self.stream, &body)?;
        let resp_body = read_frame(&mut self.stream)?;
        serde_json::from_slice(&resp_body).map_err(|e| AgentError::Protocol(e.to_string()))
    }

    pub fn get(&mut self, alias: &str) -> Result<SecretBuf, AgentError> {
        match self.call(&Request::Get {
            alias: alias.to_string(),
        })? {
            Response::Ok {
                data: ResponseData::Secret { value },
            } => {
                let buf = SecretBuf::from_slice(value.as_bytes());
                Ok(buf)
            }
            Response::Ok { .. } => Err(AgentError::Protocol("unexpected response".into())),
            Response::Err { message } if message == "locked" => Err(AgentError::Locked),
            Response::Err { message } => Err(AgentError::NotFound(message)),
        }
    }

    pub fn list(&mut self) -> Result<Vec<String>, AgentError> {
        match self.call(&Request::List)? {
            Response::Ok {
                data: ResponseData::Aliases { aliases },
            } => Ok(aliases),
            Response::Ok { .. } => Err(AgentError::Protocol("unexpected response".into())),
            Response::Err { message } => Err(AgentError::Protocol(message)),
        }
    }

    pub fn lock(&mut self) -> Result<(), AgentError> {
        match self.call(&Request::Lock)? {
            Response::Ok { .. } => Ok(()),
            Response::Err { message } => Err(AgentError::Protocol(message)),
        }
    }

    pub fn status(&mut self) -> Result<(bool, Option<u64>), AgentError> {
        match self.call(&Request::Status)? {
            Response::Ok {
                data:
                    ResponseData::Status {
                        unlocked,
                        idle_seconds,
                    },
            } => Ok((unlocked, idle_seconds)),
            _ => Err(AgentError::Protocol("unexpected response".into())),
        }
    }

    pub fn unlock(&mut self, passphrase: &SecretString) -> Result<(), AgentError> {
        use secrecy::ExposeSecret;
        match self.call(&Request::Unlock {
            passphrase: passphrase.expose_secret().to_string(),
        })? {
            Response::Ok { .. } => Ok(()),
            Response::Err { message } => Err(AgentError::Protocol(message)),
        }
    }
}

/// Connect to the agent, starting it first if it is not already running.
pub fn connect_or_start(sock_path: &Path) -> Result<Client, AgentError> {
    if let Ok(c) = Client::connect(sock_path) {
        return Ok(c);
    }
    start_daemon()?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match Client::connect(sock_path) {
            Ok(c) => return Ok(c),
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(e),
        }
    }
}

fn start_daemon() -> Result<(), AgentError> {
    let exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("agent").arg("--foreground-daemonized");
    sys::spawn_detached(&mut cmd)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

struct ServerState {
    vault_path: PathBuf,
    data: Option<VaultData>,
    passphrase: Option<SecretString>,
    last_activity: Instant,
}

impl ServerState {
    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    fn idle_for(&self) -> Duration {
        self.last_activity.elapsed()
    }

    fn lock(&mut self) {
        self.data = None;
        self.passphrase = None;
    }
}

/// Run the agent server on `sock_path` until it is idle-timed-out, locked
/// and left idle, or signalled. Blocks the calling thread.
pub fn run(sock_path: &Path, cfg: &Config) -> Result<(), AgentError> {
    config::ensure_private_dir(sock_path.parent().unwrap())
        .map_err(|e| AgentError::Protocol(e.to_string()))?;
    let lock_path = sock_path.with_file_name("agent.lock");
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(&lock_path)?;
    if !sys::try_flock_exclusive(std::os::fd::AsRawFd::as_raw_fd(&lock_file))? {
        return Err(AgentError::Protocol(
            "another agent instance is already running".into(),
        ));
    }
    let _ = std::fs::remove_file(sock_path);
    let listener = UnixListener::bind(sock_path)?;
    std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;

    sys::harden_process();
    let _ = sys::install_flag_handler(&[libc::SIGTERM, libc::SIGINT]);

    let vault_path = config::vault_path().map_err(|e| AgentError::Protocol(e.to_string()))?;
    let state = Arc::new(Mutex::new(ServerState {
        vault_path,
        data: None,
        passphrase: None,
        last_activity: Instant::now(),
    }));

    let idle_timeout = Duration::from_secs(cfg.idle_lock_minutes.max(1) * 60);
    crate::logging::event("agent: started");

    loop {
        if sys::SIGNAL_FLAG.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        {
            let mut st = state.lock().unwrap();
            if st.data.is_some() && st.idle_for() >= idle_timeout {
                st.lock();
                crate::logging::event("agent: idle timeout, locked");
            }
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let st = Arc::clone(&state);
                std::thread::spawn(move || {
                    if let Err(_e) = handle_conn(stream, st) {
                        crate::logging::event("agent: connection error");
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }

    let _ = std::fs::remove_file(sock_path);
    let _ = std::fs::remove_file(&lock_path);
    crate::logging::event("agent: shut down");
    Ok(())
}

fn handle_conn(mut stream: UnixStream, state: Arc<Mutex<ServerState>>) -> Result<(), AgentError> {
    let peer = sys::peer_uid(std::os::fd::AsRawFd::as_raw_fd(&stream))?;
    if peer != sys::geteuid() {
        crate::logging::event("agent: rejected connection from foreign uid");
        return Err(AgentError::Protocol("peer uid mismatch".into()));
    }
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    loop {
        let body = match read_frame(&mut stream) {
            Ok(b) => b,
            Err(_) => return Ok(()), // client disconnected
        };
        let req: Request = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(_) => {
                let resp = Response::Err {
                    message: "bad request".into(),
                };
                write_frame(&mut stream, &serde_json::to_vec(&resp).unwrap())?;
                continue;
            }
        };
        let resp = handle_request(req, &state);
        write_frame(&mut stream, &serde_json::to_vec(&resp).unwrap())?;
    }
}

fn handle_request(req: Request, state: &Arc<Mutex<ServerState>>) -> Response {
    let mut st = state.lock().unwrap();
    match req {
        Request::Status => {
            let unlocked = st.data.is_some();
            let idle_seconds = if unlocked {
                Some(st.idle_for().as_secs())
            } else {
                None
            };
            Response::Ok {
                data: ResponseData::Status {
                    unlocked,
                    idle_seconds,
                },
            }
        }
        Request::Lock => {
            st.lock();
            crate::logging::event("agent: locked by request");
            Response::Ok {
                data: ResponseData::None {},
            }
        }
        Request::Unlock { passphrase } => {
            let pw = SecretString::from(passphrase);
            match vault::load(&st.vault_path, &pw) {
                Ok(data) => {
                    st.data = Some(data);
                    st.passphrase = Some(pw);
                    st.touch();
                    crate::logging::event("agent: unlocked");
                    Response::Ok {
                        data: ResponseData::None {},
                    }
                }
                Err(e) => Response::Err {
                    message: e.to_string(),
                },
            }
        }
        Request::List => {
            if st.data.is_none() {
                return Response::Err {
                    message: "locked".into(),
                };
            }
            st.touch();
            let aliases = st.data.as_ref().unwrap().entries.keys().cloned().collect();
            Response::Ok {
                data: ResponseData::Aliases { aliases },
            }
        }
        Request::Get { alias } => {
            if st.data.is_none() {
                return Response::Err {
                    message: "locked".into(),
                };
            }
            st.touch();
            match st.data.as_ref().unwrap().entries.get(&alias) {
                Some(e) => {
                    crate::logging::event("agent: alias resolved");
                    // The value must cross the wire as a string; it is
                    // zeroized on the client side immediately after use by
                    // wrapping it back into a SecretBuf.
                    let value = String::from_utf8_lossy(e.secret.as_slice()).into_owned();
                    Response::Ok {
                        data: ResponseData::Secret { value },
                    }
                }
                None => {
                    crate::logging::event("agent: alias miss");
                    Response::Err {
                        message: "not found".into(),
                    }
                }
            }
        }
    }
}
