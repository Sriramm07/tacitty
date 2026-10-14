//! `SecretBackend` trait plus the four backend implementations (§8.1).
//!
//! Only `Native` is wired into `ls`/`add`/`rm`/`mv` (those operations
//! inherently need to *store* a secret, which only the native vault does).
//! `Pass`, `SecretService` and `Command` only implement `get`/`list`.

use std::io::Write;
use std::process::{Command, Stdio};

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
        let out = Command::new("pass")
            .arg("show")
            .arg(&path)
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| BackendError::Spawn {
                cmd: "pass show".into(),
                source: e,
            })?;
        if !out.status.success() {
            return Err(BackendError::NotFound(alias.to_string()));
        }
        let first_line = out.stdout.split(|&b| b == b'\n').next().unwrap_or_default();
        Ok(SecretBuf::from_slice(first_line))
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
        let out = Command::new("secret-tool")
            .args(["lookup", "application", "tacitty", "alias", alias])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| BackendError::Spawn {
                cmd: "secret-tool lookup".into(),
                source: e,
            })?;
        if !out.status.success() || out.stdout.is_empty() {
            return Err(BackendError::NotFound(alias.to_string()));
        }
        // secret-tool does not append a trailing newline, but strip one
        // defensively.
        let s = out.stdout.strip_suffix(b"\n").unwrap_or(&out.stdout);
        Ok(SecretBuf::from_slice(s))
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
        let out = Command::new(&words[0])
            .args(&words[1..])
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| BackendError::Spawn {
                cmd: words[0].clone(),
                source: e,
            })?;
        if !out.status.success() {
            return Err(BackendError::NotFound(alias.to_string()));
        }
        let first_line = out.stdout.split(|&b| b == b'\n').next().unwrap_or_default();
        Ok(SecretBuf::from_slice(first_line))
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
