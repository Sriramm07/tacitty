//! Configuration (`~/.config/tacitty/config.toml`) and filesystem locations.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::Deserialize;

use crate::sys;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendKind {
    Native,
    Pass,
    SecretService,
    Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnMiss {
    Bell,
    Literal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemoteMode {
    Confirm,
    Auto,
    Off,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RemoteConfig {
    pub mode: RemoteMode,
    pub processes: Vec<String>,
    pub prompt_regex: String,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        RemoteConfig {
            mode: RemoteMode::Confirm,
            processes: [
                "ssh",
                "mosh-client",
                "telnet",
                "docker",
                "kubectl",
                "podman",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            prompt_regex: r"(?i)(password|passphrase|passcode|pin)[^\n]*:\s*$".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PassConfig {
    pub prefix: String,
}

impl Default for PassConfig {
    fn default() -> Self {
        PassConfig {
            prefix: "tacitty".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CommandConfig {
    /// Template run to fetch a secret, e.g. `bw get password {alias}`.
    pub get: String,
    /// Optional template that prints one alias per line.
    pub list: String,
}

impl Default for CommandConfig {
    fn default() -> Self {
        CommandConfig {
            get: "bw get password {alias}".into(),
            list: String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub trigger: String,
    pub backend: BackendKind,
    pub on_miss: OnMiss,
    pub idle_lock_minutes: u64,
    pub title_indicator: bool,
    pub remote: RemoteConfig,
    pub pass: PassConfig,
    pub command: CommandConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            trigger: "@".into(),
            backend: BackendKind::Native,
            on_miss: OnMiss::Bell,
            idle_lock_minutes: 15,
            title_indicator: true,
            remote: RemoteConfig::default(),
            pass: PassConfig::default(),
            command: CommandConfig::default(),
        }
    }
}

impl Config {
    /// Load the config file; a missing file yields the defaults.
    pub fn load() -> Result<Config> {
        Self::load_from(&config_path()?)
    }

    pub fn load_from(path: &Path) -> Result<Config> {
        let cfg = match fs::read_to_string(path) {
            Ok(text) => toml::from_str::<Config>(&text)
                .with_context(|| format!("parsing {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        let t = self.trigger.as_bytes();
        if t.len() != 1 || !t[0].is_ascii_graphic() || crate::alias::is_alias_byte(t[0]) {
            bail!(
                "config: `trigger` must be a single printable ASCII character that is not a \
                 letter, digit or one of . _ / -"
            );
        }
        Regex::new(&self.remote.prompt_regex)
            .with_context(|| "config: `remote.prompt_regex` is not a valid regex")?;
        if self.backend == BackendKind::Command && self.command.get.trim().is_empty() {
            bail!("config: backend = \"command\" needs `command.get`");
        }
        Ok(())
    }

    pub fn trigger_byte(&self) -> u8 {
        self.trigger.as_bytes()[0]
    }

    pub fn prompt_regex(&self) -> Regex {
        Regex::new(&self.remote.prompt_regex).expect("validated in Config::validate")
    }
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .context("$HOME is not set")
}

fn xdg(var: &str, fallback: &str) -> Result<PathBuf> {
    match std::env::var_os(var) {
        Some(v) if !v.is_empty() && Path::new(&v).is_absolute() => Ok(PathBuf::from(v)),
        _ => Ok(home()?.join(fallback)),
    }
}

pub fn config_path() -> Result<PathBuf> {
    Ok(xdg("XDG_CONFIG_HOME", ".config")?
        .join("tacitty")
        .join("config.toml"))
}

pub fn data_dir() -> Result<PathBuf> {
    Ok(xdg("XDG_DATA_HOME", ".local/share")?.join("tacitty"))
}

pub fn vault_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("vault.age"))
}

/// Per-user runtime directory (`$XDG_RUNTIME_DIR/tacitty`, mode 0700).
pub fn runtime_dir() -> Result<PathBuf> {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(v) if !v.is_empty() && Path::new(&v).is_absolute() => {
            Ok(PathBuf::from(v).join("tacitty"))
        }
        _ => Ok(PathBuf::from(format!("/tmp/tacitty-{}", sys::geteuid()))),
    }
}

pub fn agent_sock_path() -> Result<PathBuf> {
    Ok(runtime_dir()?.join("agent.sock"))
}

pub fn agent_lock_path() -> Result<PathBuf> {
    Ok(runtime_dir()?.join("agent.lock"))
}

/// Create `dir` (and parents) if needed and make sure it is a real directory,
/// owned by us, with mode 0700. Refuses symlinks and foreign directories.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        if let Some(parent) = dir.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        fs::DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    let md = fs::symlink_metadata(dir).with_context(|| format!("stat {}", dir.display()))?;
    if !md.file_type().is_dir() {
        bail!("{} is not a directory (symlink?)", dir.display());
    }
    if md.uid() != sys::geteuid() {
        bail!("{} is not owned by you", dir.display());
    }
    if md.mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", dir.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn parses_spec_example() {
        let text = r#"
trigger = "@"
backend = "native"
on_miss = "bell"
idle_lock_minutes = 15
title_indicator = true

[remote]
mode = "confirm"
processes = ["ssh", "mosh-client", "telnet", "docker", "kubectl", "podman"]
prompt_regex = '(?i)(password|passphrase|passcode|pin)[^\n]*:\s*$'

[pass]
prefix = "tacitty"

[command]
get = "bw get password {alias}"
"#;
        let c: Config = toml::from_str(text).unwrap();
        c.validate().unwrap();
        assert_eq!(c.trigger_byte(), b'@');
        assert_eq!(c.remote.mode, RemoteMode::Confirm);
    }

    #[test]
    fn rejects_bad_trigger() {
        for t in ["", "ab", "a", "-", " ", "é"] {
            let c = Config {
                trigger: t.into(),
                ..Config::default()
            };
            assert!(c.validate().is_err(), "{t:?}");
        }
    }

    #[test]
    fn rejects_unknown_keys_and_bad_regex() {
        assert!(toml::from_str::<Config>("bogus = 1").is_err());
        let c = Config {
            remote: RemoteConfig {
                prompt_regex: "(".into(),
                ..RemoteConfig::default()
            },
            ..Config::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn backend_names() {
        for (n, k) in [
            ("native", BackendKind::Native),
            ("pass", BackendKind::Pass),
            ("secret-service", BackendKind::SecretService),
            ("command", BackendKind::Command),
        ] {
            let c: Config = toml::from_str(&format!("backend = \"{n}\"")).unwrap();
            assert_eq!(c.backend, k);
        }
    }
}
