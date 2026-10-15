//! Per-user secret agent: holds the unlocked vault in memory behind a Unix
//! socket, so `tacitty shell` doesn't have to re-prompt for the master
//! passphrase on every alias lookup (spec §8.2).
//!
//! Wire protocol: length-prefixed frames, `u32` big-endian length + JSON
//! body. Kept intentionally tiny; there is no reason for this to be a real
//! RPC framework. Secrets and the passphrase travel hex-encoded in
//! [`HexSecret`] fields, and every frame lives in a buffer that is wiped
//! after use. The socket name carries a protocol version (see
//! `config::agent_sock_path`), so a client never talks to an older agent
//! left running from before an update.

use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

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

/// A secret (or the master passphrase) on the wire: hex-encoded, so any
/// bytes survive the JSON round trip unchanged, wiped from memory on drop,
/// and never shown by `Debug`.
#[derive(Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct HexSecret(String);

impl HexSecret {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(DIGITS[(b >> 4) as usize] as char);
            s.push(DIGITS[(b & 0x0f) as usize] as char);
        }
        HexSecret(s)
    }

    /// Decode into a self-wiping buffer; `None` if it isn't valid hex.
    pub fn to_secret_buf(&self) -> Option<SecretBuf> {
        fn nibble(c: u8) -> Option<u8> {
            match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                b'A'..=b'F' => Some(c - b'A' + 10),
                _ => None,
            }
        }
        let hex = self.0.as_bytes();
        if hex.len() % 2 != 0 {
            return None;
        }
        let mut out = SecretBuf::with_capacity(hex.len() / 2);
        for pair in hex.chunks_exact(2) {
            out.push(nibble(pair[0])? << 4 | nibble(pair[1])?);
        }
        Some(out)
    }
}

impl Drop for HexSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for HexSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HexSecret(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Op {
    Get,
    List,
    Lock,
    Status,
    Unlock,
}

/// A request. Deliberately a flat struct rather than an enum: serde
/// buffers the fields of tagged/untagged enums in internal copies that are
/// never wiped, whereas struct fields deserialize straight into
/// [`HexSecret`].
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub op: Op,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<HexSecret>,
}

impl Request {
    fn op(op: Op) -> Self {
        Request {
            op,
            alias: None,
            passphrase: None,
        }
    }
}

/// A response; flat for the same reason as [`Request`].
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<HexSecret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unlocked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_seconds: Option<u64>,
}

impl Response {
    fn ok() -> Self {
        Response {
            ok: true,
            ..Default::default()
        }
    }

    fn err(message: &str) -> Self {
        Response {
            ok: false,
            message: Some(message.to_string()),
            ..Default::default()
        }
    }
}

/// Serialize `value` straight into a self-wiping buffer.
fn encode<T: Serialize>(value: &T) -> Result<SecretBuf, AgentError> {
    let mut buf = SecretBuf::with_capacity(256);
    serde_json::to_writer(&mut buf, value).map_err(|e| AgentError::Protocol(e.to_string()))?;
    Ok(buf)
}

fn write_frame<W: Write>(w: &mut W, body: &[u8]) -> std::io::Result<()> {
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(body)?;
    w.flush()
}

fn read_frame<R: Read>(r: &mut R) -> Result<Zeroizing<Vec<u8>>, AgentError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(AgentError::Protocol("frame too large".into()));
    }
    let mut body = Zeroizing::new(vec![0u8; len as usize]);
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
        let body = encode(req)?;
        write_frame(&mut self.stream, body.as_slice())?;
        let resp_body = read_frame(&mut self.stream)?;
        serde_json::from_slice(&resp_body).map_err(|e| AgentError::Protocol(e.to_string()))
    }

    pub fn get(&mut self, alias: &str) -> Result<SecretBuf, AgentError> {
        let resp = self.call(&Request {
            alias: Some(alias.to_string()),
            ..Request::op(Op::Get)
        })?;
        if !resp.ok {
            return Err(match resp.message.as_deref() {
                Some("locked") => AgentError::Locked,
                Some("not found") => AgentError::NotFound(alias.to_string()),
                other => AgentError::Protocol(other.unwrap_or("agent error").to_string()),
            });
        }
        resp.secret
            .as_ref()
            .and_then(HexSecret::to_secret_buf)
            .ok_or_else(|| AgentError::Protocol("unexpected response".into()))
    }

    pub fn list(&mut self) -> Result<Vec<String>, AgentError> {
        let resp = self.call(&Request::op(Op::List))?;
        match (resp.ok, resp.aliases) {
            (true, Some(aliases)) => Ok(aliases),
            (true, None) => Err(AgentError::Protocol("unexpected response".into())),
            (false, _) => Err(AgentError::Protocol(
                resp.message.unwrap_or_else(|| "agent error".into()),
            )),
        }
    }

    pub fn lock(&mut self) -> Result<(), AgentError> {
        let resp = self.call(&Request::op(Op::Lock))?;
        if resp.ok {
            Ok(())
        } else {
            Err(AgentError::Protocol(
                resp.message.unwrap_or_else(|| "agent error".into()),
            ))
        }
    }

    pub fn status(&mut self) -> Result<(bool, Option<u64>), AgentError> {
        let resp = self.call(&Request::op(Op::Status))?;
        match (resp.ok, resp.unlocked) {
            (true, Some(unlocked)) => Ok((unlocked, resp.idle_seconds)),
            _ => Err(AgentError::Protocol("unexpected response".into())),
        }
    }

    pub fn unlock(&mut self, passphrase: &SecretString) -> Result<(), AgentError> {
        use secrecy::ExposeSecret;
        let resp = self.call(&Request {
            passphrase: Some(HexSecret::from_bytes(passphrase.expose_secret().as_bytes())),
            ..Request::op(Op::Unlock)
        })?;
        if resp.ok {
            Ok(())
        } else {
            Err(AgentError::Protocol(
                resp.message.unwrap_or_else(|| "agent error".into()),
            ))
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
    }
}

/// Run the agent server on `sock_path` until it is idle-timed-out, locked
/// and left idle, or signalled. Blocks the calling thread.
pub fn run(sock_path: &Path, cfg: &Config) -> Result<(), AgentError> {
    config::ensure_private_dir(sock_path.parent().unwrap())
        .map_err(|e| AgentError::Protocol(e.to_string()))?;
    let lock_path = config::agent_lock_path().map_err(|e| AgentError::Protocol(e.to_string()))?;
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
        let resp = match serde_json::from_slice::<Request>(&body) {
            Ok(req) => handle_request(req, &state),
            Err(_) => Response::err("bad request"),
        };
        write_frame(&mut stream, encode(&resp)?.as_slice())?;
    }
}

fn handle_request(req: Request, state: &Arc<Mutex<ServerState>>) -> Response {
    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
    match req.op {
        Op::Status => {
            let unlocked = st.data.is_some();
            Response {
                unlocked: Some(unlocked),
                idle_seconds: unlocked.then(|| st.idle_for().as_secs()),
                ..Response::ok()
            }
        }
        Op::Lock => {
            st.lock();
            crate::logging::event("agent: locked by request");
            Response::ok()
        }
        Op::Unlock => {
            let Some(pass_bytes) = req.passphrase.as_ref().and_then(HexSecret::to_secret_buf)
            else {
                return Response::err("bad request");
            };
            let Ok(pass_str) = std::str::from_utf8(pass_bytes.as_slice()) else {
                return Response::err("bad request");
            };
            let pw = SecretString::from(pass_str.to_string());
            match vault::load(&st.vault_path, &pw) {
                Ok(data) => {
                    // The passphrase is only needed to decrypt; it is not
                    // kept (pw is wiped when it goes out of scope).
                    st.data = Some(data);
                    st.touch();
                    crate::logging::event("agent: unlocked");
                    Response::ok()
                }
                Err(e) => Response::err(&e.to_string()),
            }
        }
        Op::List => {
            let Some(data) = st.data.as_ref() else {
                return Response::err("locked");
            };
            let aliases = data.entries.keys().cloned().collect();
            st.touch();
            Response {
                aliases: Some(aliases),
                ..Response::ok()
            }
        }
        Op::Get => {
            let Some(data) = st.data.as_ref() else {
                return Response::err("locked");
            };
            let found = req
                .alias
                .as_deref()
                .and_then(|a| data.entries.get(a))
                .map(|e| HexSecret::from_bytes(e.secret.as_slice()));
            st.touch();
            match found {
                Some(secret) => {
                    crate::logging::event("agent: alias resolved");
                    Response {
                        secret: Some(secret),
                        ..Response::ok()
                    }
                }
                None => {
                    crate::logging::event("agent: alias miss");
                    Response::err("not found")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_secret_round_trips_any_bytes() {
        let all: Vec<u8> = (0..=255).collect();
        let h = HexSecret::from_bytes(&all);
        assert_eq!(h.to_secret_buf().unwrap().as_slice(), all.as_slice());
        assert!(HexSecret("abc".into()).to_secret_buf().is_none());
        assert!(HexSecret("zz".into()).to_secret_buf().is_none());
    }

    #[test]
    fn debug_never_shows_secrets() {
        let req = Request {
            passphrase: Some(HexSecret::from_bytes(b"hunter2")),
            ..Request::op(Op::Unlock)
        };
        let shown = format!("{req:?}");
        assert!(!shown.contains(&HexSecret::from_bytes(b"hunter2").0));
        assert!(shown.contains("redacted"));
    }

    #[test]
    fn wire_format_round_trips() {
        let resp = Response {
            secret: Some(HexSecret::from_bytes("pä55\u{1}".as_bytes())),
            ..Response::ok()
        };
        let enc = encode(&resp).unwrap();
        let back: Response = serde_json::from_slice(enc.as_slice()).unwrap();
        assert!(back.ok);
        assert_eq!(
            back.secret.unwrap().to_secret_buf().unwrap().as_slice(),
            "pä55\u{1}".as_bytes()
        );
    }
}
