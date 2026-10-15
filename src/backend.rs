//! `SecretBackend` trait plus the four backend implementations (§8.1).
//!
//! Only `Native` is wired into `ls`/`add`/`rm`/`mv` (those operations
//! inherently need to *store* a secret, which only the native vault does).
//! `Pass`, `SecretService` and `Command` only implement `get`/`list`.

use std::io::{Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use thiserror::Error;

pub use crate::config::BackendKind;
use crate::config::{CommandConfig, Config, PassConfig};
use crate::secret::SecretBuf;
use crate::vault;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("no secret stored for alias `{0}`")]
    NotFound(String),
    #[error(transparent)]
    Vault(#[from] vault::VaultError),
    #[error("running `{cmd}`: {source}")]
    Spawn {
        cmd: String,
        #[source]
        source: std::io::Error,
    },
    #[error("`{cmd}` exited with status {status}")]
    NonZeroExit { cmd: String, status: String },
    #[error("{0}")]
    Other(String),
}

/// How long a helper program (`pass`, `secret-tool`, a `command` template)
/// may take before it is killed. The wrapper waits on it with the user's
/// terminal paused, so a hung helper must not freeze the terminal forever.
const HELPER_TIMEOUT: Duration = Duration::from_secs(30);

/// Run `cmd` with stdin closed, capturing stdout into a self-wiping buffer
/// (stderr is discarded). The whole call never takes much longer than
/// [`HELPER_TIMEOUT`].
///
/// The helper runs in a new session (so also its own process group) with
/// no controlling terminal: it can't read the user's terminal, which the
/// wrapper has in raw mode, so a helper that wants to prompt fails at once
/// instead of hanging. On timeout the whole group is killed, including
/// background processes it started that would otherwise keep its output
/// open.
fn run_helper(cmd: &mut Command, name: &str) -> Result<(ExitStatus, SecretBuf), BackendError> {
    use std::os::unix::process::CommandExt;
    use std::sync::mpsc;

    let spawn_err = |e| BackendError::Spawn {
        cmd: name.to_string(),
        source: e,
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // SAFETY: only the async-signal-safe setsid() runs between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().map_err(spawn_err)?;
    let pgid = child.id() as i32;
    let kill_group = || {
        let _ = crate::sys::kill(-pgid, libc::SIGKILL);
    };

    // Read stdout on a separate thread and hand the result over a channel,
    // so waiting for it can be bounded by the deadline too.
    let mut stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut out = SecretBuf::with_capacity(256);
        let mut chunk = zeroize::Zeroizing::new([0u8; 4096]);
        loop {
            match stdout.read(&mut chunk[..]) {
                Ok(0) | Err(_) => break,
                // Cap what we keep: a secret is at most a few KiB.
                Ok(n) if out.len() < 64 * 1024 => out.extend_from_slice(&chunk[..n]),
                Ok(_) => {}
            }
        }
        let _ = tx.send(out);
    });

    let timed_out = || {
        BackendError::Other(format!(
            "`{name}` did not finish within {}s",
            HELPER_TIMEOUT.as_secs()
        ))
    };
    let deadline = Instant::now() + HELPER_TIMEOUT;
    let status = loop {
        match child.try_wait().map_err(spawn_err)? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                kill_group();
                let _ = child.wait();
                return Err(timed_out());
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    // The helper has exited. Its output normally ends right away; if
    // something it left running still holds the pipe open, stop that too.
    let out = match rx.recv_timeout(Duration::from_millis(500)) {
        Ok(out) => out,
        Err(_) => {
            kill_group();
            rx.recv_timeout(Duration::from_secs(1))
                .map_err(|_| timed_out())?
        }
    };
    Ok((status, out))
}

/// The first line of `out` (without its `\n`, or `\r\n`), as a secret.
fn first_line(out: &SecretBuf) -> SecretBuf {
    let line = out.split(|&b| b == b'\n').next().unwrap_or_default();
    SecretBuf::from_slice(line.strip_suffix(b"\r").unwrap_or(line))
}

pub trait SecretBackend {
    fn get(&self, alias: &str) -> Result<SecretBuf, BackendError>;
    /// List known aliases. Not every backend can do this cheaply; those
    /// that can't return an empty list.
    fn list(&self) -> Result<Vec<String>, BackendError>;
}

// ---------------------------------------------------------------------------
// Native
// ---------------------------------------------------------------------------

pub struct NativeBackend<'a> {
    pub data: &'a vault::VaultData,
}

impl<'a> SecretBackend for NativeBackend<'a> {
    fn get(&self, alias: &str) -> Result<SecretBuf, BackendError> {
        self.data
            .entries
            .get(alias)
            .map(|e| e.secret.clone())
            .ok_or_else(|| BackendError::NotFound(alias.to_string()))
    }

    fn list(&self) -> Result<Vec<String>, BackendError> {
        Ok(self.data.entries.keys().cloned().collect())
    }
}

// ---------------------------------------------------------------------------
// pass
// ---------------------------------------------------------------------------

pub struct PassBackend {
    pub cfg: PassConfig,
}

impl SecretBackend for PassBackend {
    fn get(&self, alias: &str) -> Result<SecretBuf, BackendError> {
        let path = format!("{}/{}", self.cfg.prefix, alias);
        let (status, out) = run_helper(Command::new("pass").arg("show").arg(&path), "pass show")?;
        if !status.success() {
            return Err(BackendError::NotFound(alias.to_string()));
        }
        Ok(first_line(&out))
    }

    fn list(&self) -> Result<Vec<String>, BackendError> {
        let out = Command::new("pass")
            .arg("ls")
            .arg(&self.cfg.prefix)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| BackendError::Spawn {
                cmd: "pass ls".into(),
                source: e,
            })?;
        if !out.status.success() {
            return Ok(Vec::new());
        }
        // `pass ls` prints a tree; do a best-effort leaf extraction.
        let text = String::from_utf8_lossy(&out.stdout);
        let names = text
            .lines()
            .filter_map(|l| {
                let trimmed = l.trim_start_matches(['├', '└', '─', '│', ' ']);
                if trimmed.is_empty() || trimmed == self.cfg.prefix {
                    None
                } else {
                    Some(trimmed.trim().to_string())
                }
            })
            .collect();
        Ok(names)
    }
}

// ---------------------------------------------------------------------------
// Secret Service (libsecret via `secret-tool`)
// ---------------------------------------------------------------------------
//
// A D-Bus client library would pull in a large async dependency tree; the
// `secret-tool` CLI (part of libsecret's own tools package) gives the same
// result with none of that, at the cost of requiring the tool on PATH.

pub struct SecretServiceBackend;

impl SecretBackend for SecretServiceBackend {
    fn get(&self, alias: &str) -> Result<SecretBuf, BackendError> {
        let (status, out) = run_helper(
            Command::new("secret-tool").args(["lookup", "application", "tacitty", "alias", alias]),
            "secret-tool lookup",
        )?;
        if !status.success() || out.is_empty() {
            return Err(BackendError::NotFound(alias.to_string()));
        }
        // secret-tool does not append a trailing newline, but strip one
        // defensively.
        Ok(first_line(&out))
    }

    fn list(&self) -> Result<Vec<String>, BackendError> {
        Ok(Vec::new()) // secret-tool has no generic "list by attribute" mode
    }
}

/// Store a secret via `secret-tool store` (used by `tacitty add` only when
/// `backend = "secret-service"`). Secrets are piped over stdin, never argv.
pub fn secret_service_put(alias: &str, secret: &[u8]) -> Result<(), BackendError> {
    let mut child = Command::new("secret-tool")
        .args([
            "store",
            "--label",
            &format!("tacitty: {alias}"),
            "application",
            "tacitty",
            "alias",
            alias,
        ])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| BackendError::Spawn {
            cmd: "secret-tool store".into(),
            source: e,
        })?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(secret)
        .map_err(|e| BackendError::Spawn {
            cmd: "secret-tool store".into(),
            source: e,
        })?;
    let status = child.wait().map_err(|e| BackendError::Spawn {
        cmd: "secret-tool store".into(),
        source: e,
    })?;
    if !status.success() {
        return Err(BackendError::NonZeroExit {
            cmd: "secret-tool store".into(),
            status: status.to_string(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

pub struct CommandBackend {
    pub cfg: CommandConfig,
}

/// Substitute `{alias}` in a template, then split it shell-word-style
/// (simple whitespace + quote handling — good enough for `bw get password
/// {alias}` style templates; no shell is invoked, so no injection risk).
fn split_template(template: &str, alias: &str) -> Result<Vec<String>, BackendError> {
    let filled = template.replace("{alias}", alias);
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut chars = filled.chars().peekable();
    let mut in_word = false;
    while let Some(c) = chars.next() {
        match c {
            '\'' | '"' => {
                in_word = true;
                let quote = c;
                for c2 in chars.by_ref() {
                    if c2 == quote {
                        break;
                    }
                    cur.push(c2);
                }
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    if words.is_empty() {
        return Err(BackendError::Other("empty command template".into()));
    }
    Ok(words)
}

impl SecretBackend for CommandBackend {
    fn get(&self, alias: &str) -> Result<SecretBuf, BackendError> {
        let words = split_template(&self.cfg.get, alias)?;
        let (status, out) = run_helper(Command::new(&words[0]).args(&words[1..]), &words[0])?;
        if !status.success() {
            return Err(BackendError::NotFound(alias.to_string()));
        }
        Ok(first_line(&out))
    }

    fn list(&self) -> Result<Vec<String>, BackendError> {
        if self.cfg.list.trim().is_empty() {
            return Ok(Vec::new());
        }
        let words = split_template(&self.cfg.list, "")?;
        let out = Command::new(&words[0])
            .args(&words[1..])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| BackendError::Spawn {
                cmd: words[0].clone(),
                source: e,
            })?;
        if !out.status.success() {
            return Ok(Vec::new());
        }
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect())
    }
}

/// Look up `alias` via whichever backend `cfg` selects, unlocking the
/// native vault with `passphrase` when needed. Non-native backends do not
/// need a passphrase, so `passphrase` may be `None` for them.
pub fn get_via_config(
    cfg: &Config,
    alias: &str,
    native_data: Option<&vault::VaultData>,
) -> Result<SecretBuf, BackendError> {
    match cfg.backend {
        BackendKind::Native => {
            let data = native_data
                .ok_or_else(|| BackendError::Other("native vault is not unlocked".into()))?;
            NativeBackend { data }.get(alias)
        }
        BackendKind::Pass => PassBackend {
            cfg: cfg.pass.clone(),
        }
        .get(alias),
        BackendKind::SecretService => SecretServiceBackend.get(alias),
        BackendKind::Command => CommandBackend {
            cfg: cfg.command.clone(),
        }
        .get(alias),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_output_is_captured() {
        let (status, out) = run_helper(Command::new("printf").arg("abc\\n"), "printf").unwrap();
        assert!(status.success());
        assert_eq!(first_line(&out).as_slice(), b"abc");
    }

    #[test]
    fn background_child_holding_stdout_does_not_block() {
        let start = Instant::now();
        let (status, out) = run_helper(
            Command::new("sh").args(["-c", "echo abc; sleep 30 &"]),
            "sh",
        )
        .unwrap();
        assert!(status.success());
        assert_eq!(first_line(&out).as_slice(), b"abc");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn helper_has_no_terminal_to_prompt_on() {
        let (status, _) =
            run_helper(Command::new("sh").args(["-c", "exec 3</dev/tty"]), "sh").unwrap();
        assert!(!status.success(), "helper could open the terminal");
    }
}
