use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use secrecy::SecretString;

use tacitty::agent::{self, Client};
use tacitty::alias;
use tacitty::autostart;
use tacitty::config::{self, Config};
use tacitty::export;
use tacitty::secret::SecretBuf;
use tacitty::sys;
use tacitty::update;
use tacitty::vault;
use tacitty::wrapper::{self, RunOptions};

/// `println!`, except that a closed stdout (`tacitty ls | head -1`) ends the
/// program quietly, the way command-line tools normally do, instead of
/// panicking.
macro_rules! outln {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        if let Err(e) = writeln!(std::io::stdout(), $($arg)*) {
            stdout_failed(e)
        }
    }};
}

/// `print!` with the same handling as [`outln!`].
macro_rules! out {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        if let Err(e) = write!(std::io::stdout(), $($arg)*) {
            stdout_failed(e)
        }
    }};
}

fn stdout_failed(e: std::io::Error) -> ! {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        std::process::exit(141); // what a shell reports for SIGPIPE
    }
    eprintln!("tacitty: writing output: {e}");
    std::process::exit(1);
}

#[derive(Parser)]
#[command(
    name = "tacitty",
    version,
    about = "Prompt-aware password alias injector for Linux terminals"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the native vault and set the master passphrase.
    Init {
        /// Don't make new terminals start inside `tacitty shell`.
        #[arg(long)]
        no_autostart: bool,
    },
    /// Store a secret under an alias (prompts with echo off).
    Add {
        alias: String,
        #[arg(long)]
        generate: bool,
        #[arg(long, default_value_t = 20)]
        length: usize,
    },
    /// Remove an alias.
    Rm { alias: String },
    /// Rename an alias.
    Mv { old: String, new: String },
    /// List aliases and timestamps (never secrets).
    Ls,
    /// Print a secret to stdout (refuses a TTY unless --force).
    Get {
        alias: String,
        #[arg(long)]
        force: bool,
    },
    /// Write aliases to an encrypted file to share with someone.
    #[command(after_help = "\
With no --to / --to-file, the file is protected by an export passphrase
(asked twice, at least 12 characters). Quote SSH keys given to --to:
  --to \"ssh-ed25519 AAAA... alice@laptop\"
The file is a standard age file holding CXF JSON.")]
    Export {
        /// Aliases to export (default: all of them).
        #[arg(value_name = "ALIAS")]
        aliases: Vec<String>,
        /// File to write (created with mode 0600).
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
        /// Encrypt to this public key: age (age1...), ssh-ed25519 or
        /// ssh-rsa. Repeatable.
        #[arg(long = "to", value_name = "KEY")]
        to: Vec<String>,
        /// Encrypt to every public key in FILE, one per line (an
        /// authorized_keys or GitHub .keys file). Repeatable.
        #[arg(long = "to-file", value_name = "FILE")]
        to_file: Vec<PathBuf>,
        /// Write ASCII-armored text (for pasting into chat or email).
        #[arg(long)]
        armor: bool,
        /// Replace FILE if it already exists.
        #[arg(long)]
        force: bool,
    },
    /// Add aliases from a file made by `tacitty export`.
    Import {
        /// The export file (binary or armored).
        file: PathBuf,
        /// Age identity file or SSH private key to decrypt with. Repeatable.
        /// Default: ~/.ssh/id_ed25519 and ~/.ssh/id_rsa.
        #[arg(short = 'i', long = "identity", value_name = "IDENTITY")]
        identity: Vec<PathBuf>,
        /// Replace aliases that already exist in your vault.
        #[arg(long)]
        overwrite: bool,
    },
    /// Run $SHELL (or a given command) inside the pty wrapper.
    Shell {
        /// Used by the shell rc hook: if the wrapper can't start, exit with
        /// a reserved code so the hook falls back to the plain shell.
        #[arg(long, hide = true)]
        autostart: bool,
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Start every new terminal inside `tacitty shell` (bash/zsh).
    Enable,
    /// Stop new terminals from starting inside `tacitty shell`.
    Disable,
    /// Update tacitty to the latest release.
    Update {
        /// Only check whether a newer release exists.
        #[arg(long)]
        check: bool,
    },
    /// Run the per-user secret agent (normally started automatically).
    Agent {
        #[arg(long, hide = true)]
        foreground_daemonized: bool,
    },
    /// Lock the running agent's vault.
    Lock,
    /// Unlock the vault (prompts for the master passphrase).
    Unlock,
    /// Show agent lock status.
    Status,
    /// Check termios detection, agent reachability, backends, nesting.
    Doctor,
    /// Print the config file path.
    Config,
}

fn main() -> Result<()> {
    // Every command may hold the decrypted vault or the master passphrase
    // in memory, so all of them refuse core dumps and debugger attachment.
    sys::harden_process();
    // Writes to a closed pipe (a helper program, the agent socket, or
    // stdout) return an error instead of killing the process; stdout is
    // handled by `outln!` / `out!`.
    sys::ignore_sigpipe();
    let cli = Cli::parse();
    let code = match cli.cmd {
        Cmd::Init { no_autostart } => cmd_init(no_autostart),
        Cmd::Add {
            alias,
            generate,
            length,
        } => cmd_add(&alias, generate, length),
        Cmd::Rm { alias } => cmd_rm(&alias),
        Cmd::Mv { old, new } => cmd_mv(&old, &new),
        Cmd::Ls => cmd_ls(),
        Cmd::Export {
            aliases,
            output,
            to,
            to_file,
            armor,
            force,
        } => cmd_export(&aliases, &output, &to, &to_file, armor, force),
        Cmd::Import {
            file,
            identity,
            overwrite,
        } => cmd_import(&file, &identity, overwrite),
        Cmd::Get { alias, force } => cmd_get(&alias, force),
        Cmd::Shell { autostart, command } => cmd_shell(command, autostart),
        Cmd::Enable => cmd_enable(),
        Cmd::Disable => cmd_disable(),
        Cmd::Update { check } => cmd_update(check),
        Cmd::Agent {
            foreground_daemonized: _,
        } => cmd_agent(),
        Cmd::Lock => cmd_lock(),
        Cmd::Unlock => cmd_unlock(),
        Cmd::Status => cmd_status(),
        Cmd::Doctor => cmd_doctor(),
        Cmd::Config => cmd_config_path(),
    }?;
    std::process::exit(code);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn read_passphrase(prompt: &str) -> Result<SecretString> {
    out!("{prompt}");
    std::io::stdout().flush().ok();
    let buf = read_secret_from_tty()?;
    outln!();
    Ok(SecretString::from(
        String::from_utf8_lossy(buf.as_slice()).into_owned(),
    ))
}

/// Read one line from `/dev/tty` with echo off (spec §9: `add` reads from
/// `/dev/tty`, not stdin, so it still works when stdin is piped).
fn read_secret_from_tty() -> Result<SecretBuf> {
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("opening /dev/tty")?;
    let fd = tty.as_raw_fd();
    let saved = sys::tcgetattr(fd)?;
    let mut noecho = saved;
    noecho.c_lflag &= !(libc::ECHO);
    noecho.c_lflag |= libc::ICANON | libc::ECHONL;
    // TCSANOW, not TCSAFLUSH: a flush would discard any bytes that landed
    // in the kernel's input queue in the (however brief) window between
    // this process printing the prompt and reaching this tcsetattr call —
    // silently truncating fast-typed or pasted input. TCSANOW changes the
    // echo behavior for everything from here on without touching whatever
    // is already queued.
    sys::tcsetattr(fd, libc::TCSANOW, &noecho)?;

    let mut buf = SecretBuf::new();
    let mut byte = [0u8; 1];
    let result = loop {
        match sys::read_fd(fd, &mut byte) {
            Ok(0) => break Ok(()),
            Ok(_) => {
                if byte[0] == b'\n' || byte[0] == b'\r' {
                    break Ok(());
                }
                if buf.len() < 4096 {
                    buf.push(byte[0]);
                }
            }
            Err(e) => break Err(e),
        }
    };
    let _ = sys::tcsetattr(fd, libc::TCSANOW, &saved);
    result.context("reading from /dev/tty")?;
    Ok(buf)
}

fn confirm_passphrase() -> Result<SecretString> {
    let first = read_passphrase("New master passphrase: ")?;
    let second = read_passphrase("Confirm master passphrase: ")?;
    use secrecy::ExposeSecret;
    if first.expose_secret() != second.expose_secret() {
        bail!("passphrases did not match");
    }
    if first.expose_secret().is_empty() {
        bail!("passphrase must not be empty");
    }
    Ok(first)
}

fn load_config() -> Result<Config> {
    Config::load()
}

fn agent_client(cfg: &Config) -> Result<Client> {
    let _ = cfg; // reserved for future per-backend routing
    let sock = config::agent_sock_path()?;
    agent::connect_or_start(&sock).map_err(|e| anyhow::anyhow!("{e}"))
}

fn ensure_unlocked(client: &mut Client) -> Result<()> {
    let (unlocked, _) = client.status().map_err(|e| anyhow::anyhow!("{e}"))?;
    if unlocked {
        return Ok(());
    }
    let pass = read_passphrase("Master passphrase: ")?;
    client
        .unlock(&pass)
        .map_err(|e| anyhow::anyhow!("unlocking vault: {e}"))
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

fn cmd_init(no_autostart: bool) -> Result<i32> {
    let path = config::vault_path()?;
    if vault::exists(&path) {
        bail!(
            "a vault already exists at {} (delete it first if you really want to start over)",
            path.display()
        );
    }
    let pass = confirm_passphrase()?;
    vault::create(&path, &pass).map_err(|e| anyhow::anyhow!("{e}"))?;
    outln!("Created vault at {}", path.display());
    if !no_autostart {
        // The vault exists at this point; an rc-file problem shouldn't make
        // init look like it failed.
        match autostart::enable() {
            Ok(files) => print_enabled(&files),
            Err(e) => eprintln!("tacitty: could not enable auto-start: {e:#}"),
        }
    }
    outln!("Run `tacitty add <alias>` to store your first secret.");
    Ok(0)
}

fn print_enabled(files: &[std::path::PathBuf]) {
    for f in files {
        outln!("Auto-start enabled in {}", f.display());
    }
    outln!("New terminals now start inside tacitty.");
    outln!("Run `tacitty disable` to turn this off (or set NO_TACITTY=1 for one shell).");
}

fn cmd_enable() -> Result<i32> {
    print_enabled(&autostart::enable()?);
    Ok(0)
}

fn cmd_disable() -> Result<i32> {
    let files = autostart::disable()?;
    if files.is_empty() {
        outln!("Auto-start was not enabled.");
    }
    for f in &files {
        outln!("Auto-start removed from {}", f.display());
    }
    if !files.is_empty() {
        outln!(
            "New terminals will start your normal shell. Run `tacitty enable` to turn it back on."
        );
    }
    Ok(0)
}

fn cmd_add(alias_name: &str, generate: bool, length: usize) -> Result<i32> {
    alias::validate(alias_name).map_err(|e| anyhow::anyhow!("{e}"))?;
    let path = config::vault_path()?;
    if !vault::exists(&path) {
        bail!("no vault found (run `tacitty init` first)");
    }

    let secret = if generate {
        let secret = generate_secret(length)?;
        outln!(
            "Generated a {}-character secret for @{alias_name}.",
            secret.len()
        );
        secret
    } else {
        let s1 = read_secret_prompted("Secret: ")?;
        let s2 = read_secret_prompted("Confirm secret: ")?;
        if s1.as_slice() != s2.as_slice() {
            bail!("secrets did not match");
        }
        s1
    };
    vault::validate_secret(secret.as_slice()).map_err(|e| anyhow::anyhow!(e))?;

    let cfg = load_config()?;
    if cfg.backend == tacitty::backend::BackendKind::Native {
        // Writing a new entry needs the passphrase directly, to re-encrypt
        // the vault file (the agent only ever holds a read-only in-memory
        // copy, and is never asked to write). Ask once here, then tell the
        // agent to drop its now-stale cached copy, if it happens to be
        // running.
        let pass = read_passphrase("Master passphrase: ")?;
        let mut data = vault::load(&path, &pass).map_err(|e| anyhow::anyhow!("{e}"))?;
        data.put(alias_name, secret.as_slice());
        vault::save(&path, &pass, &data).map_err(|e| anyhow::anyhow!("{e}"))?;
        if let Ok(mut c) = Client::connect(&config::agent_sock_path()?) {
            let _ = c.lock();
        }
        outln!("Saved @{alias_name}.");
    } else if cfg.backend == tacitty::backend::BackendKind::SecretService {
        tacitty::backend::secret_service_put(alias_name, secret.as_slice())
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        outln!("Saved @{alias_name} to the Secret Service keyring.");
    } else {
        bail!(
            "`tacitty add` only writes to the native or secret-service backends; \
             manage aliases for the configured backend directly"
        );
    }
    Ok(0)
}

fn read_secret_prompted(prompt: &str) -> Result<SecretBuf> {
    out!("{prompt}");
    std::io::stdout().flush().ok();
    let s = read_secret_from_tty()?;
    outln!();
    Ok(s)
}

fn generate_secret(length: usize) -> Result<SecretBuf> {
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.";
    // Largest multiple of the charset size that fits in a byte; random
    // bytes at or above it are discarded so every character is equally
    // likely (plain `% len` would favour the first few).
    const LIMIT: u8 = (256 / CHARSET.len() * CHARSET.len()) as u8;
    let len = length.clamp(8, vault::MAX_SECRET_LEN);
    let mut out = SecretBuf::with_capacity(len);
    let mut raw = SecretBuf::from_slice(&[0u8; 64]);
    while out.len() < len {
        let mut chunk = [0u8; 64];
        sys::getrandom(&mut chunk)?;
        raw.clear();
        raw.extend_from_slice(&chunk);
        zeroize::Zeroize::zeroize(&mut chunk);
        for &b in raw.as_slice() {
            if b < LIMIT && out.len() < len {
                out.push(CHARSET[(b as usize) % CHARSET.len()]);
            }
        }
    }
    Ok(out)
}

fn cmd_rm(alias_name: &str) -> Result<i32> {
    let path = config::vault_path()?;
    let pass = read_passphrase("Master passphrase: ")?;
    let mut data = vault::load(&path, &pass).map_err(|e| anyhow::anyhow!("{e}"))?;
    if data.entries.remove(alias_name).is_none() {
        bail!("no such alias: {alias_name}");
    }
    vault::save(&path, &pass, &data).map_err(|e| anyhow::anyhow!("{e}"))?;
    if let Ok(mut c) = agent_client(&load_config()?) {
        let _ = c.lock();
    }
    outln!("Removed @{alias_name}.");
    Ok(0)
}

fn cmd_mv(old: &str, new: &str) -> Result<i32> {
    alias::validate(new).map_err(|e| anyhow::anyhow!("{e}"))?;
    let path = config::vault_path()?;
    let pass = read_passphrase("Master passphrase: ")?;
    let mut data = vault::load(&path, &pass).map_err(|e| anyhow::anyhow!("{e}"))?;
    let entry = data
        .entries
        .remove(old)
        .ok_or_else(|| anyhow::anyhow!("no such alias: {old}"))?;
    data.entries.insert(new.to_string(), entry);
    vault::save(&path, &pass, &data).map_err(|e| anyhow::anyhow!("{e}"))?;
    if let Ok(mut c) = agent_client(&load_config()?) {
        let _ = c.lock();
    }
    outln!("Renamed @{old} to @{new}.");
    Ok(0)
}

fn cmd_ls() -> Result<i32> {
    let cfg = load_config()?;
    let path = config::vault_path()?;
    if !vault::exists(&path) {
        outln!("(no vault yet — run `tacitty init`)");
        return Ok(0);
    }
    let pass = read_passphrase("Master passphrase: ")?;
    let data = vault::load(&path, &pass).map_err(|e| anyhow::anyhow!("{e}"))?;
    if data.entries.is_empty() {
        outln!("(no aliases yet — run `tacitty add <alias>`)");
        return Ok(0);
    }
    for (alias_name, e) in &data.entries {
        outln!(
            "{:<32}  created {}  updated {}",
            format!("@{alias_name}"),
            fmt_time(e.created),
            fmt_time(e.updated)
        );
    }
    let _ = cfg;
    Ok(0)
}

fn cmd_export(
    aliases: &[String],
    output: &Path,
    to: &[String],
    to_file: &[PathBuf],
    armor: bool,
    force: bool,
) -> Result<i32> {
    // Everything that can fail without a passphrase is checked first, so
    // nobody types passphrases only to hit a bad key or an existing file.
    export::check_output_path(output, force)?;
    let mut recipients = Vec::new();
    for key in to {
        recipients.push(export::parse_recipient(key).map_err(|e| anyhow::anyhow!("--to: {e}"))?);
    }
    for file in to_file {
        recipients.extend(export::read_recipients_file(file).map_err(|e| anyhow::anyhow!(e))?);
    }
    let path = config::vault_path()?;
    if !vault::exists(&path) {
        bail!("no vault found (run `tacitty init` first)");
    }

    let pass = read_passphrase("Master passphrase: ")?;
    let data = vault::load(&path, &pass).map_err(|e| anyhow::anyhow!("{e}"))?;
    drop(pass);
    let mut names: Vec<&str> = Vec::new();
    if aliases.is_empty() {
        names.extend(data.entries.keys().map(String::as_str));
    } else {
        for a in aliases {
            if !data.entries.contains_key(a) {
                bail!("no such alias: {a} (nothing was exported)");
            }
            if !names.contains(&a.as_str()) {
                names.push(a);
            }
        }
    }
    if names.is_empty() {
        bail!("the vault has no aliases to export");
    }
    let entries: Vec<export::ExportEntry> = names
        .iter()
        .map(|&a| {
            let e = &data.entries[a];
            export::ExportEntry {
                alias: a,
                secret: e.secret.as_slice(),
                created: e.created,
                updated: e.updated,
            }
        })
        .collect();
    let plain = export::encode_cxf(&entries, vault::now_unix())?;

    let recipient_count = recipients.len();
    let protection = if recipients.is_empty() {
        let first = read_passphrase("Export passphrase: ")?;
        let second = read_passphrase("Confirm export passphrase: ")?;
        use secrecy::ExposeSecret;
        if first.expose_secret() != second.expose_secret() {
            bail!("passphrases did not match");
        }
        export::check_passphrase(&first).map_err(|e| anyhow::anyhow!(e))?;
        export::Protection::Passphrase(first)
    } else {
        export::Protection::Recipients(recipients)
    };
    let cipher = export::encrypt(&plain, &protection, armor)?;
    drop(plain);
    export::write_export_file(output, &cipher, force)?;

    let list: Vec<String> = names.iter().map(|a| format!("@{a}")).collect();
    outln!(
        "Exported {} alias{} to {}: {}",
        names.len(),
        if names.len() == 1 { "" } else { "es" },
        output.display(),
        list.join(", ")
    );
    let form = if armor { "armored" } else { "binary" };
    if recipient_count == 0 {
        outln!("Protected by the export passphrase ({form} age file).");
        outln!("Send the passphrase over a different channel than the file.");
    } else {
        outln!(
            "Encrypted to {recipient_count} public key{} ({form} age file).",
            if recipient_count == 1 { "" } else { "s" }
        );
    }
    Ok(0)
}

/// Ask for an SSH private key's passphrase (only when it is needed).
fn ask_key_passphrase(prompt: &str) -> Option<SecretString> {
    read_passphrase(prompt).ok()
}

fn cmd_import(file: &Path, identity: &[PathBuf], overwrite: bool) -> Result<i32> {
    let path = config::vault_path()?;
    if !vault::exists(&path) {
        bail!("no vault found (run `tacitty init` first)");
    }
    if load_config()?.backend != tacitty::backend::BackendKind::Native {
        bail!("`tacitty import` writes to the native vault, but another backend is configured");
    }
    let cipher = export::read_export_file(file)?;
    let kind = export::inspect(&cipher).map_err(|e| anyhow::anyhow!("{}: {e}", file.display()))?;

    let plain = if kind.passphrase {
        let pass = read_passphrase("Export file passphrase: ")?;
        export::decrypt_with_passphrase(&cipher, &pass)?
    } else {
        let mut files: Vec<PathBuf> = identity.to_vec();
        if files.is_empty() {
            let home = std::env::var_os("HOME").map(PathBuf::from);
            for name in ["id_ed25519", "id_rsa"] {
                if let Some(p) = home.as_ref().map(|h| h.join(".ssh").join(name)) {
                    if p.is_file() {
                        files.push(p);
                    }
                }
            }
            if files.is_empty() {
                bail!(
                    "{} is encrypted to public keys; pass your private key with -i \
                     (no ~/.ssh/id_ed25519 or ~/.ssh/id_rsa found)",
                    file.display()
                );
            }
        }
        let mut ids = Vec::new();
        for f in &files {
            ids.extend(export::load_identities(f, ask_key_passphrase)?);
        }
        match export::decrypt_with_identities(&cipher, &ids) {
            Err(export::ExportError::NoMatchingIdentity) => {
                let tried: Vec<String> = files.iter().map(|f| f.display().to_string()).collect();
                bail!(
                    "{} was not encrypted to any of your keys (tried {})",
                    file.display(),
                    tried.join(", ")
                );
            }
            other => other?,
        }
    };
    let decoded = export::decode_cxf(&plain)?;
    drop(plain);

    let report = if decoded.items.is_empty() {
        export::ImportReport {
            skipped: decoded.skipped,
            ..Default::default()
        }
    } else {
        let pass = read_passphrase("Master passphrase: ")?;
        let mut data = vault::load(&path, &pass).map_err(|e| anyhow::anyhow!("{e}"))?;
        let report = export::merge_into(&mut data, decoded, overwrite);
        if !report.added.is_empty() || !report.replaced.is_empty() {
            vault::save(&path, &pass, &data).map_err(|e| anyhow::anyhow!("{e}"))?;
            if let Ok(mut c) = Client::connect(&config::agent_sock_path()?) {
                let _ = c.lock();
            }
        }
        report
    };

    let at = |v: &[String]| v.iter().map(|a| format!("@{a}")).collect::<Vec<_>>();
    let mut imported = at(&report.added);
    imported.extend(
        at(&report.replaced)
            .into_iter()
            .map(|a| format!("{a} (replaced)")),
    );
    if imported.is_empty() {
        outln!("Imported nothing.");
    } else {
        outln!("Imported {}: {}", imported.len(), imported.join(", "));
    }
    if !report.skipped.is_empty() {
        outln!("Skipped {}:", report.skipped.len());
        for s in &report.skipped {
            outln!("  {}: {}", s.title, s.reason);
        }
    }
    Ok(0)
}

fn fmt_time(unix: u64) -> String {
    // Minimal dependency-free formatting: seconds since epoch as UTC date.
    let days = unix / 86400;
    let secs_of_day = unix % 86400;
    let (h, m, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

/// Howard Hinnant's days-from-civil algorithm, inverted (public domain).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn cmd_update(check: bool) -> Result<i32> {
    match update::run(check)? {
        update::Outcome::UpToDate { current } => {
            outln!("tacitty {current} is already the latest version.")
        }
        update::Outcome::Available { current, latest } => {
            outln!("tacitty {latest} is available (you have {current}). Run `tacitty update` to install it.")
        }
        update::Outcome::Updated { from, to, path } => {
            outln!("Updated tacitty {from} -> {to} at {}.", path.display());
            outln!("New terminals use it right away; already-open ones keep the old version until closed.");
        }
    }
    Ok(0)
}

fn cmd_get(alias_name: &str, force: bool) -> Result<i32> {
    if sys::isatty(1) && !force {
        bail!("refusing to print a secret to a terminal; pass --force to override");
    }
    let cfg = load_config()?;
    let mut client = agent_client(&cfg)?;
    ensure_unlocked(&mut client)?;
    let secret = client.get(alias_name).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut out = std::io::stdout();
    out.write_all(secret.as_slice())?;
    Ok(0)
}

fn cmd_shell(command: Vec<String>, autostart: bool) -> Result<i32> {
    let result = load_config().and_then(|cfg| {
        let opts = RunOptions {
            command: if command.is_empty() {
                None
            } else {
                Some(command)
            },
        };
        wrapper::run(cfg, opts).map_err(|e| anyhow::anyhow!("{e}"))
    });
    match result {
        Err(e) if autostart => {
            eprintln!("tacitty: {e:#} (continuing without tacitty)");
            Ok(autostart::FALLBACK_EXIT_CODE)
        }
        other => other,
    }
}

fn cmd_agent() -> Result<i32> {
    let cfg = load_config()?;
    let sock = config::agent_sock_path()?;
    agent::run(&sock, &cfg).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(0)
}

fn cmd_lock() -> Result<i32> {
    let cfg = load_config()?;
    let mut client = agent_client(&cfg)?;
    client.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
    outln!("Locked.");
    Ok(0)
}

fn cmd_unlock() -> Result<i32> {
    let cfg = load_config()?;
    let mut client = agent_client(&cfg)?;
    ensure_unlocked(&mut client)?;
    outln!("Unlocked.");
    Ok(0)
}

fn cmd_status() -> Result<i32> {
    let cfg = load_config()?;
    match agent_client(&cfg) {
        Ok(mut c) => match c.status() {
            Ok((true, idle)) => {
                outln!(
                    "unlocked (idle {}s, auto-lock after {}m)",
                    idle.unwrap_or(0),
                    cfg.idle_lock_minutes
                );
            }
            Ok((false, _)) => outln!("locked"),
            Err(e) => outln!("agent reachable but errored: {e}"),
        },
        Err(_) => outln!("agent not running"),
    }
    Ok(0)
}

fn cmd_doctor() -> Result<i32> {
    let cfg = load_config()?;
    let mut ok = true;

    outln!("tacitty doctor");
    outln!("==============");

    // termios detection sanity: are we even on a tty?
    if sys::isatty(0) {
        outln!("[ok]   stdin is a tty");
    } else {
        outln!("[warn] stdin is not a tty (run this interactively for a full check)");
    }

    match config::config_path() {
        Ok(p) => outln!("[ok]   config path: {}", p.display()),
        Err(e) => {
            outln!("[fail] config path: {e}");
            ok = false;
        }
    }
    if let Err(e) = cfg.validate() {
        outln!("[fail] config: {e}");
        ok = false;
    } else {
        outln!("[ok]   config parses and validates");
    }

    match config::vault_path() {
        Ok(p) if vault::exists(&p) => match vault::check_permissions(&p) {
            Ok(()) => outln!("[ok]   vault at {} has safe permissions", p.display()),
            Err(e) => {
                outln!("[fail] vault permissions: {e}");
                ok = false;
            }
        },
        Ok(p) => outln!(
            "[warn] no vault yet at {} (run `tacitty init`)",
            p.display()
        ),
        Err(e) => {
            outln!("[fail] vault path: {e}");
            ok = false;
        }
    }

    match config::agent_sock_path() {
        Ok(sock) => match agent::Client::connect(&sock) {
            Ok(mut c) => match c.status() {
                Ok((unlocked, _)) => outln!(
                    "[ok]   agent reachable at {} ({})",
                    sock.display(),
                    if unlocked { "unlocked" } else { "locked" }
                ),
                Err(e) => outln!("[warn] agent reachable but status failed: {e}"),
            },
            Err(_) => outln!("[info] agent not running yet (starts automatically on first use)"),
        },
        Err(e) => {
            outln!("[fail] runtime dir: {e}");
            ok = false;
        }
    }

    match autostart::enabled_in() {
        Ok(files) if files.is_empty() => {
            outln!("[info] auto-start is off (run `tacitty enable` to wrap every new terminal)")
        }
        Ok(files) => {
            for f in files {
                outln!("[ok]   auto-start enabled in {}", f.display());
            }
        }
        Err(e) => outln!("[warn] could not check auto-start: {e:#}"),
    }

    if std::env::var_os("TACITTY_ACTIVE").is_some() {
        outln!("[warn] already inside a tacitty shell (nested `shell` would not re-wrap)");
    } else {
        outln!("[ok]   not currently nested");
    }

    match cfg.backend {
        tacitty::backend::BackendKind::Native => outln!("[ok]   backend: native"),
        tacitty::backend::BackendKind::Pass => {
            let found = which("pass");
            outln!(
                "[{}]   backend: pass ({})",
                if found { "ok" } else { "warn" },
                if found {
                    "found on PATH"
                } else {
                    "not found on PATH"
                }
            );
        }
        tacitty::backend::BackendKind::SecretService => {
            let found = which("secret-tool");
            outln!(
                "[{}]   backend: secret-service ({})",
                if found { "ok" } else { "warn" },
                if found {
                    "found on PATH"
                } else {
                    "secret-tool not found on PATH"
                }
            );
        }
        tacitty::backend::BackendKind::Command => {
            outln!("[ok]   backend: command (`{}`)", cfg.command.get)
        }
    }

    for pinentry in ["pinentry-curses", "pinentry-gnome3", "pinentry-qt"] {
        if which(pinentry) {
            outln!(
                "[info] {pinentry} is on PATH — its prompts run in raw mode and are NOT \
                 detected; switch gpg-agent's pinentry-program to pinentry-tty if you want \
                 alias expansion at gpg prompts"
            );
        }
    }

    outln!();
    outln!(
        "{}",
        if ok {
            "All checks passed."
        } else {
            "Some checks failed."
        }
    );
    Ok(if ok { 0 } else { 1 })
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

fn cmd_config_path() -> Result<i32> {
    outln!("{}", config::config_path()?.display());
    Ok(0)
}
