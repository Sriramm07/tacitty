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
use tacitty::group;
use tacitty::resolver::{ResolveOutcome, Resolver};
use tacitty::run::{classify_arg, ArgAction};
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
    about = "Prompt-aware password alias injector for Linux and macOS terminals"
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
        /// Put the alias in this group (default: the vault's default group;
        /// an existing alias stays in its group).
        #[arg(short, long, value_name = "GROUP")]
        group: Option<String>,
        #[arg(long)]
        generate: bool,
        #[arg(long, default_value_t = 20)]
        length: usize,
    },
    /// Remove an alias.
    Rm { alias: String },
    /// Rename an alias (it stays in its group).
    Mv { old: String, new: String },
    /// List aliases by group, with timestamps (never secrets).
    Ls {
        /// Only list this group.
        #[arg(short, long, value_name = "GROUP")]
        group: Option<String>,
    },
    /// Organise aliases into groups.
    #[command(after_help = "\
Every alias is in exactly one group. Alias names stay unique across all
groups, so @proddb works the same whichever group it is in. Groups are for
listing (`tacitty ls -g prod`) and sharing (`tacitty export -g prod ...`).")]
    Group {
        #[command(subcommand)]
        cmd: GroupCmd,
    },
    /// Print a secret to stdout (refuses a TTY unless --force).
    Get {
        alias: String,
        #[arg(long)]
        force: bool,
    },
    /// Run a command, replacing `@alias` arguments with the real secret.
    #[command(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        after_help = "\
Each argument that is exactly `@alias` (or `--flag=@alias`) is replaced with
the secret stored under that alias before the command runs; everything else,
including the command's own flags, is passed through untouched. Use `@@name`
for a literal `@name`, and note that `user@host` or `me@example.com` is left
alone (only a whole argument starting with the trigger is substituted).

  tacitty run swaks --auth-password @smtp -tls ...
  tacitty run mysql --host db --user app --password=@proddb

Unlike a password prompt, `run` puts the secret in the command's arguments,
where it is visible in `ps` and /proc/<pid>/cmdline. It keeps the secret out
of your shell history, scrollback and clipboard, but not out of `ps`; for
that, prefer the tool's own password prompt or a password-command such as
RESTIC_PASSWORD_COMMAND=\"tacitty get restic\"."
    )]
    Run {
        /// The command to run, then its arguments (`@alias` ones are
        /// substituted). Put `--` before it to be safe with leading dashes.
        #[arg(value_name = "COMMAND", required = true, num_args = 1..)]
        args: Vec<String>,
    },
    /// Write aliases to an encrypted file to share with someone.
    #[command(after_help = "\
Exports the named aliases plus every alias in the named groups; with
neither, every alias. Group membership is kept in the file.

With --with-key, the one file can be opened by each listed person with
their own private key:
  tacitty export -g prod --with-key alice.pub --with-key bob.pub -o prod.tacitty
Quote keys given directly: --with-key \"ssh-ed25519 AAAA... alice@laptop\"
Without --with-key, the file is protected by an export passphrase (asked
twice, at least 12 characters). The file is a standard age file holding
CXF JSON.")]
    Export {
        /// Aliases to export.
        #[arg(value_name = "ALIAS")]
        aliases: Vec<String>,
        /// Export every alias in this group. Repeatable.
        #[arg(short, long = "group", value_name = "GROUP")]
        groups: Vec<String>,
        /// File to write (created with mode 0600).
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
        /// Encrypt to a public key (age1..., ssh-ed25519 or ssh-rsa), or to
        /// every key in a file, one per line (a .pub, authorized_keys or
        /// GitHub .keys file). Repeatable.
        #[arg(long = "with-key", value_name = "KEY_OR_FILE")]
        with_key: Vec<String>,
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
        /// Put every imported alias in this group. Default: the group it
        /// had in the file, or your default group.
        #[arg(short, long, value_name = "GROUP")]
        group: Option<String>,
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

#[derive(Subcommand)]
enum GroupCmd {
    /// List groups and how many aliases each holds.
    Ls,
    /// Move aliases into a group (created if it doesn't exist).
    Move {
        /// Aliases to move.
        #[arg(value_name = "ALIAS", required = true)]
        aliases: Vec<String>,
        /// The group to move them into.
        #[arg(long = "to", value_name = "GROUP")]
        to: String,
    },
    /// Rename a group (if it is the default group, the default follows).
    Rename {
        /// The group's current name.
        old: String,
        /// Its new name (must not be an existing group).
        new: String,
    },
    /// Delete a group, moving its aliases into the default group.
    Rm {
        /// The group to delete (not the default group). No alias or
        /// secret is deleted.
        group: String,
    },
    /// Show the default group for new aliases, or set it.
    Default {
        /// Make this the default group.
        group: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    // Every command may hold the decrypted vault or the master passphrase
    // in memory, so all of them refuse core dumps and debugger attachment.
    // The one exception is a `tacitty shell` started inside another one:
    // it holds nothing and only execs the plain shell (`wrapper::run`), and
    // on macOS the debugger block would survive that exec and stick to the
    // user's shell.
    if !(matches!(cli.cmd, Cmd::Shell { .. }) && wrapper::is_nested()) {
        sys::harden_process();
    }
    // Writes to a closed pipe (a helper program, the agent socket, or
    // stdout) return an error instead of killing the process; stdout is
    // handled by `outln!` / `out!`.
    sys::ignore_sigpipe();
    let code = match cli.cmd {
        Cmd::Init { no_autostart } => cmd_init(no_autostart),
        Cmd::Add {
            alias,
            group,
            generate,
            length,
        } => cmd_add(&alias, group.as_deref(), generate, length),
        Cmd::Rm { alias } => cmd_rm(&alias),
        Cmd::Mv { old, new } => cmd_mv(&old, &new),
        Cmd::Ls { group } => cmd_ls(group.as_deref()),
        Cmd::Group { cmd } => cmd_group(cmd),
        Cmd::Export {
            aliases,
            groups,
            output,
            with_key,
            armor,
            force,
        } => cmd_export(&aliases, &groups, &output, &with_key, armor, force),
        Cmd::Import {
            file,
            identity,
            group,
            overwrite,
        } => cmd_import(&file, &identity, group.as_deref(), overwrite),
        Cmd::Get { alias, force } => cmd_get(&alias, force),
        Cmd::Run { args } => cmd_run(args),
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
    // Refuse rather than "repair" invalid UTF-8: a lossy conversion would
    // leave an unwiped copy and map different inputs to the same passphrase.
    let text = std::str::from_utf8(buf.as_slice())
        .map_err(|_| anyhow::anyhow!("the passphrase is not valid UTF-8 text"))?;
    Ok(SecretString::from(text.to_string()))
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
    // Ctrl-C (or a TERM/HUP) while typing must not kill us with echo still
    // switched off: catch it, restore the terminal below, then give up.
    let signals = sys::SignalGuard::new().ok();
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
        match sys::read_once(fd, &mut byte) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                if signals.as_ref().is_some_and(|g| g.triggered()) {
                    break Err(std::io::Error::other("cancelled"));
                }
            }
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
    drop(signals);
    if let Err(e) = result {
        if e.to_string() == "cancelled" {
            outln!();
            bail!("cancelled");
        }
        return Err(e).context("reading from /dev/tty");
    }
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

/// Ask for the master passphrase and load the native vault.
fn open_vault() -> Result<(PathBuf, SecretString, vault::VaultData)> {
    let path = config::vault_path()?;
    if !vault::exists(&path) {
        bail!("no vault found (run `tacitty init` first)");
    }
    let pass = read_passphrase("Master passphrase: ")?;
    let data = vault::load(&path, &pass).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok((path, pass, data))
}

/// Save the vault, then lock the running agent (if there is one) so it
/// drops its now-stale copy and reloads the file on the next unlock.
fn save_vault(path: &Path, pass: &SecretString, data: &vault::VaultData) -> Result<()> {
    vault::save(path, pass, data).map_err(|e| anyhow::anyhow!("{e}"))?;
    if let Ok(mut c) = Client::connect(&config::agent_sock_path()?) {
        let _ = c.lock();
    }
    Ok(())
}

/// Validate a group name given on the command line.
fn check_group(name: &str) -> Result<()> {
    group::validate(name)
        .map_err(|e| anyhow::anyhow!("invalid group name `{}`: {e}", export::display_title(name)))
}

/// `@a, @b, @c`
fn at_list<S: AsRef<str>>(aliases: &[S]) -> String {
    aliases
        .iter()
        .map(|a| format!("@{}", a.as_ref()))
        .collect::<Vec<_>>()
        .join(", ")
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
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

fn cmd_add(alias_name: &str, group: Option<&str>, generate: bool, length: usize) -> Result<i32> {
    alias::validate(alias_name).map_err(|e| anyhow::anyhow!("{e}"))?;
    if let Some(g) = group {
        check_group(g)?;
    }
    let path = config::vault_path()?;
    if !vault::exists(&path) {
        bail!("no vault found (run `tacitty init` first)");
    }
    let cfg = load_config()?;
    if group.is_some() && cfg.backend != tacitty::backend::BackendKind::Native {
        bail!("groups are only available with the native vault backend");
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
    if secret.as_slice().first() == Some(&b'~') {
        eprintln!(
            "Note: this secret starts with `~`. Inside an ssh session a `~` at \
             the start of a line is ssh's escape character (`~.` disconnects), \
             so typing it there behaves the same as typing it by hand would."
        );
    }

    if cfg.backend == tacitty::backend::BackendKind::Native {
        // Writing a new entry needs the passphrase directly, to re-encrypt
        // the vault file (the agent only ever holds a read-only in-memory
        // copy, and is never asked to write). Ask once here, then tell the
        // agent to drop its now-stale cached copy, if it happens to be
        // running.
        let (path, pass, mut data) = open_vault()?;
        match group {
            Some(g) => data.put_in(alias_name, secret.as_slice(), g),
            None => data.put(alias_name, secret.as_slice()),
        }
        save_vault(&path, &pass, &data)?;
        outln!(
            "Saved @{alias_name} in group {}.",
            data.entries[alias_name].group
        );
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
    let (path, pass, mut data) = open_vault()?;
    if data.entries.remove(alias_name).is_none() {
        bail!("no such alias: {alias_name}");
    }
    save_vault(&path, &pass, &data)?;
    outln!("Removed @{alias_name}.");
    Ok(0)
}

fn cmd_mv(old: &str, new: &str) -> Result<i32> {
    alias::validate(new).map_err(|e| anyhow::anyhow!("{e}"))?;
    let (path, pass, mut data) = open_vault()?;
    if old == new {
        return Ok(0);
    }
    // Never replace another alias's secret by renaming onto it.
    if data.entries.contains_key(new) {
        bail!("@{new} already exists; remove it first (`tacitty rm {new}`) or pick another name");
    }
    // The entry, group included, moves to its new name unchanged.
    let entry = data
        .entries
        .remove(old)
        .ok_or_else(|| anyhow::anyhow!("no such alias: {old}"))?;
    data.entries.insert(new.to_string(), entry);
    save_vault(&path, &pass, &data)?;
    outln!("Renamed @{old} to @{new}.");
    Ok(0)
}

fn cmd_ls(only: Option<&str>) -> Result<i32> {
    if let Some(g) = only {
        check_group(g)?;
    }
    let path = config::vault_path()?;
    if !vault::exists(&path) {
        outln!("(no vault yet — run `tacitty init`)");
        return Ok(0);
    }
    let (_, _, data) = open_vault()?;
    if let Some(g) = only {
        if !data.has_group(g) {
            bail!("no such group: {g}");
        }
    } else if data.entries.is_empty() {
        outln!("(no aliases yet — run `tacitty add <alias>`)");
        return Ok(0);
    }
    let mut first = true;
    for (g, count) in data.groups() {
        if only.is_some_and(|o| o != g) {
            continue;
        }
        if !first {
            outln!();
        }
        first = false;
        let mark = if g == data.default_group {
            " (default)"
        } else {
            ""
        };
        outln!("{g}{mark}");
        if count == 0 {
            outln!("  (no aliases)");
        }
        for (alias_name, e) in data.entries.iter().filter(|(_, e)| e.group == g) {
            // e.g. a secret stored before the length limit was lowered: it
            // is kept, but would be refused at a prompt, so say so.
            let note = match vault::validate_secret(e.secret.as_slice()) {
                Ok(()) => String::new(),
                Err(why) => format!("  (can't be sent: {why}; replace it with `tacitty add`)"),
            };
            outln!(
                "  {:<32}  created {}  updated {}{note}",
                format!("@{alias_name}"),
                fmt_time(e.created),
                fmt_time(e.updated)
            );
        }
    }
    Ok(0)
}

fn cmd_group(cmd: GroupCmd) -> Result<i32> {
    // Names are checked before the passphrase is asked for.
    match &cmd {
        GroupCmd::Ls | GroupCmd::Default { group: None } => {}
        GroupCmd::Move { to, .. } => check_group(to)?,
        GroupCmd::Rename { old, new } => {
            check_group(old)?;
            check_group(new)?;
        }
        GroupCmd::Rm { group } | GroupCmd::Default { group: Some(group) } => check_group(group)?,
    }
    let (path, pass, mut data) = open_vault()?;
    let fail = |e: String| anyhow::anyhow!(e);
    match cmd {
        GroupCmd::Ls => {
            for (g, count) in data.groups() {
                let mark = if g == data.default_group {
                    "  (default)"
                } else {
                    ""
                };
                outln!("{g:<24}  {:>11}{mark}", plural(count, "alias", "aliases"));
            }
        }
        GroupCmd::Move { mut aliases, to } => {
            let mut seen = std::collections::BTreeSet::new();
            aliases.retain(|a| seen.insert(a.clone()));
            let moved = data.move_to_group(&aliases, &to).map_err(fail)?;
            if !moved.is_empty() {
                save_vault(&path, &pass, &data)?;
                outln!("Moved {} to group {to}.", at_list(&moved));
            }
            let already: Vec<&String> = aliases.iter().filter(|a| !moved.contains(a)).collect();
            if !already.is_empty() {
                outln!("Already in group {to}: {}.", at_list(&already));
            }
        }
        GroupCmd::Rename { old, new } => {
            let was_default = data.default_group == old;
            let n = data.rename_group(&old, &new).map_err(fail)?;
            save_vault(&path, &pass, &data)?;
            outln!(
                "Renamed group {old} to {new} ({}).",
                plural(n, "alias", "aliases")
            );
            if was_default {
                outln!("{new} is still the default group for new aliases.");
            }
        }
        GroupCmd::Rm { group } => {
            let moved = data.remove_group(&group).map_err(fail)?;
            save_vault(&path, &pass, &data)?;
            outln!("Removed group {group}.");
            if !moved.is_empty() {
                outln!("Moved {} to group {}.", at_list(&moved), data.default_group);
            }
        }
        GroupCmd::Default { group: None } => {
            outln!(
                "New aliases go into group {} (the default group).",
                data.default_group
            );
        }
        GroupCmd::Default { group: Some(g) } => {
            if data.default_group == g {
                outln!("{g} is already the default group.");
            } else {
                data.set_default_group(&g).map_err(fail)?;
                save_vault(&path, &pass, &data)?;
                outln!("New aliases now go into group {g}.");
            }
        }
    }
    Ok(0)
}

fn cmd_export(
    aliases: &[String],
    groups: &[String],
    output: &Path,
    with_key: &[String],
    armor: bool,
    force: bool,
) -> Result<i32> {
    // Everything that can fail without a passphrase is checked first, so
    // nobody types passphrases only to hit a bad key or an existing file.
    export::check_output_path(output, force)?;
    for g in groups {
        check_group(g)?;
    }
    let mut recipients = Vec::new();
    for value in with_key {
        recipients.extend(
            export::recipients_from_arg(value).map_err(|e| anyhow::anyhow!("--with-key: {e}"))?,
        );
    }

    let (_, pass, data) = open_vault()?;
    drop(pass);
    for g in groups {
        if !data.has_group(g) {
            bail!("no such group: {g} (nothing was exported)");
        }
    }
    for a in aliases {
        if !data.entries.contains_key(a) {
            bail!("no such alias: {a} (nothing was exported)");
        }
    }
    let everything = aliases.is_empty() && groups.is_empty();
    let selected: Vec<(&str, &vault::Entry)> = data
        .entries
        .iter()
        .filter(|(a, e)| everything || aliases.contains(a) || groups.contains(&e.group))
        .map(|(a, e)| (a.as_str(), e))
        .collect();
    if selected.is_empty() {
        if everything {
            bail!("the vault has no aliases to export");
        }
        bail!("nothing to export: the selected groups have no aliases");
    }
    let entries: Vec<export::ExportEntry> = selected
        .iter()
        .map(|&(a, e)| export::ExportEntry {
            alias: a,
            group: &e.group,
            secret: e.secret.as_slice(),
            created: e.created,
            updated: e.updated,
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

    outln!(
        "Exported {} to {}:",
        plural(selected.len(), "alias", "aliases"),
        output.display()
    );
    print_by_group(
        selected
            .iter()
            .map(|(a, e)| (e.group.as_str(), format!("@{a}"))),
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

/// Print `  group <name>: <label>, <label>` lines, one per group, in name order.
fn print_by_group<'a>(items: impl Iterator<Item = (&'a str, String)>) {
    let mut by_group: std::collections::BTreeMap<&str, Vec<String>> = Default::default();
    for (g, label) in items {
        by_group.entry(g).or_default().push(label);
    }
    for (g, labels) in by_group {
        outln!("  group {g}: {}", labels.join(", "));
    }
}

fn cmd_import(
    file: &Path,
    identity: &[PathBuf],
    group: Option<&str>,
    overwrite: bool,
) -> Result<i32> {
    if let Some(g) = group {
        check_group(g)?;
    }
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
        let (path, pass, mut data) = open_vault()?;
        if group.is_none() {
            for title in &decoded.bad_collections {
                outln!(
                    "Note: collection `{title}` is not a valid group name; its aliases go \
                     into group {}.",
                    data.default_group
                );
            }
        }
        let report = export::merge_into(&mut data, decoded, overwrite, group);
        if !report.imported.is_empty() {
            save_vault(&path, &pass, &data)?;
        }
        report
    };

    if report.imported.is_empty() {
        outln!("Imported nothing.");
    } else {
        outln!(
            "Imported {}:",
            plural(report.imported.len(), "alias", "aliases")
        );
        print_by_group(report.imported.iter().map(|i| {
            let label = if i.replaced {
                format!("@{} (replaced)", i.alias)
            } else {
                format!("@{}", i.alias)
            };
            (i.group.as_str(), label)
        }));
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

/// `tacitty run [--] <command> [args...]`: run `<command>`, replacing any
/// `@alias` argument with the real secret first. The secret ends up in the
/// child's argv — visible in `ps` — which is the documented tradeoff for
/// this command (it protects shell history, scrollback and the clipboard,
/// not `ps`).
fn cmd_run(args: Vec<String>) -> Result<i32> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    // clap guarantees at least one argument (`num_args = 1..`, required), but
    // check rather than index blindly.
    let mut it = args.into_iter();
    let command = it
        .next()
        .ok_or_else(|| anyhow::anyhow!("run: a command is required"))?;
    let rest: Vec<String> = it.collect();

    let cfg = load_config()?;
    let trigger = cfg.trigger_byte();
    let trigger_ch = trigger as char;

    // Resolve every `@alias` up front, so an unknown alias (or any resolver
    // error) stops us before the command runs. The command name itself
    // (argv[0] of the child) is never substituted.
    let mut resolver: Option<Resolver> = None;
    let mut resolved: Vec<OsString> = Vec::with_capacity(rest.len());
    for arg in &rest {
        match classify_arg(arg, trigger) {
            ArgAction::Passthrough => resolved.push(OsString::from(arg)),
            ArgAction::Escape(literal) => resolved.push(OsString::from(literal)),
            ArgAction::Alias { flag, name } => {
                if resolver.is_none() {
                    resolver = Some(Resolver::new(cfg.clone())?);
                }
                let r = resolver.as_mut().expect("resolver initialised just above");
                // The resolver validates the secret with `vault::validate_secret`
                // (control characters etc. would break the target command),
                // returning `Error` on failure, so nothing invalid reaches argv.
                let secret = resolve_run_alias(r, &name, trigger_ch)?;
                // The one unavoidable plaintext copy: the flag prefix plus the
                // secret bytes, moved straight into the child's argv. Not kept
                // anywhere else, never printed.
                let mut bytes = flag.into_bytes();
                bytes.extend_from_slice(secret.as_slice());
                resolved.push(OsString::from_vec(bytes));
            }
        }
    }

    let status = std::process::Command::new(&command)
        .args(&resolved)
        .status()
        .with_context(|| format!("running `{command}`"))?;
    Ok(wrapper::exit_code_of(status))
}

/// Resolve one alias for `tacitty run`, prompting for the master passphrase
/// and unlocking if the native vault is locked (as `cmd_get` does). Fails
/// without running on an unknown alias or any resolver error.
fn resolve_run_alias(resolver: &mut Resolver, name: &str, trigger: char) -> Result<SecretBuf> {
    let mut asked = false;
    loop {
        match resolver.resolve(name) {
            ResolveOutcome::Found(secret) => return Ok(secret),
            ResolveOutcome::NotFound => {
                bail!("no such alias: {name} (use {trigger}{trigger} for a literal {trigger})")
            }
            ResolveOutcome::Locked if !asked => {
                asked = true;
                let pass = read_passphrase("Master passphrase: ")?;
                resolver
                    .unlock(&pass)
                    .map_err(|e| anyhow::anyhow!("unlocking vault: {e}"))?;
            }
            ResolveOutcome::Locked => bail!("vault is locked"),
            ResolveOutcome::Error(e) => bail!("resolving @{name}: {e}"),
        }
    }
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

    if wrapper::is_nested() {
        outln!("[ok]   this terminal is wrapped by tacitty");
    } else {
        outln!("[info] this terminal is not wrapped by tacitty (open a new terminal if auto-start is on, or run `tacitty shell`)");
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
