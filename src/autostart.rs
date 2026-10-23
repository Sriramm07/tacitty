//! `tacitty enable` / `tacitty disable`: make every new interactive terminal
//! start inside `tacitty shell` without any manual setup.
//!
//! tacitty deliberately does NOT become the user's login shell (`chsh`):
//! the login shell is also used for `ssh host cmd`, `scp`, cron and the
//! desktop session, all of which run `<shell> -c ...`, and `tacitty shell`
//! itself spawns `$SHELL`, so it would recurse into itself. Instead, a
//! clearly marked block is added to the user's shell rc file(s) that hands
//! each *interactive* shell over to the wrapper. If the wrapper cannot
//! start, it exits with [`FALLBACK_EXIT_CODE`] and the hook falls through
//! to the plain shell, so a broken install can never lock anyone out of
//! their terminal.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Exit code `tacitty shell --autostart` uses to tell the rc hook "the
/// wrapper never started; keep running the plain shell".
pub const FALLBACK_EXIT_CODE: i32 = 213;

const BEGIN_MARKER: &str = "# >>> tacitty autostart >>>";
const END_MARKER: &str = "# <<< tacitty autostart <<<";

/// A shell whose rc file tacitty knows how to hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Bash,
    Zsh,
}

impl Shell {
    const ALL: [Shell; 2] = [Shell::Bash, Shell::Zsh];

    fn name(self) -> &'static str {
        match self {
            Shell::Bash => "bash",
            Shell::Zsh => "zsh",
        }
    }

    pub fn rc_path(self) -> Result<PathBuf> {
        Ok(match self {
            Shell::Bash => home()?.join(".bashrc"),
            Shell::Zsh => match std::env::var_os("ZDOTDIR") {
                Some(d) if !d.is_empty() && Path::new(&d).is_absolute() => {
                    PathBuf::from(d).join(".zshrc")
                }
                _ => home()?.join(".zshrc"),
            },
        })
    }
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .context("$HOME is not set")
}

/// The user's login shell, if it is one we can hook.
fn login_shell() -> Option<Shell> {
    let shell = std::env::var("SHELL").ok()?;
    let name = Path::new(&shell).file_name()?.to_str()?;
    Shell::ALL.into_iter().find(|s| s.name() == name)
}

/// Quote `s` for a POSIX shell as a single-quoted word.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The rc-file block that hands interactive shells to `bin shell`.
pub fn render_block(bin: &Path) -> String {
    let bin = sh_quote(&bin.to_string_lossy());
    format!(
        "{BEGIN_MARKER}
# Managed by `tacitty enable` / `tacitty disable`; set NO_TACITTY=1 to skip.
case $- in *i*)
  if [ \"${{TACITTY_ACTIVE:-}}\" != \"$(tty 2>/dev/null)\" ] && [ -z \"${{NO_TACITTY:-}}\" ] && [ -t 0 ] && [ -x {bin} ]; then
    {bin} shell --autostart
    __tacitty_rc=$?
    if [ \"$__tacitty_rc\" -ne {FALLBACK_EXIT_CODE} ]; then exit \"$__tacitty_rc\"; fi
    unset __tacitty_rc
  fi
;; esac
{END_MARKER}
"
    )
}

/// Byte range of an existing block (including its trailing newline), if any.
fn block_range(content: &str) -> Option<(usize, usize)> {
    let start = content.find(BEGIN_MARKER)?;
    let end_rel = content[start..].find(END_MARKER)?;
    let mut end = start + end_rel + END_MARKER.len();
    if content[end..].starts_with('\n') {
        end += 1;
    }
    Some((start, end))
}

pub fn has_block(content: &str) -> bool {
    block_range(content).is_some()
}

/// Insert `block`, replacing an existing tacitty block in place if present,
/// otherwise appending it at the end.
pub fn upsert_block(content: &str, block: &str) -> String {
    if let Some((start, end)) = block_range(content) {
        return format!("{}{}{}", &content[..start], block, &content[end..]);
    }
    let mut out = content.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(block);
    out
}

/// Remove the tacitty block, or `None` if there wasn't one.
pub fn remove_block(content: &str) -> Option<String> {
    let (start, end) = block_range(content)?;
    let mut head = content[..start].to_string();
    // Drop the blank separator line `upsert_block` added before the block.
    if head.ends_with("\n\n") {
        head.pop();
    }
    Some(format!("{head}{}", &content[end..]))
}

/// Is `exe` (a canonical path) installed by a package manager? That's
/// anything under `/usr` or `/opt`: distro packages, and on macOS also
/// Homebrew (`/opt/homebrew`, and `/usr/local/Cellar`, where its
/// `/usr/local/bin` symlinks resolve to) and MacPorts (`/opt/local`).
pub fn is_packaged_install(exe: &Path) -> bool {
    exe.starts_with("/usr") || exe.starts_with("/opt")
}

/// For a Homebrew install, the running binary resolves to a versioned path
/// (`<prefix>/Cellar/tacitty/<version>/bin/tacitty`) that `brew upgrade` /
/// `brew cleanup` deletes, which would silently switch auto-start off. These
/// are the stable paths Homebrew keeps pointing at the current version, in
/// order of preference; empty for anything that isn't a Cellar path.
pub fn stable_packaged_path(exe: &Path) -> Vec<PathBuf> {
    let parts: Vec<_> = exe.components().collect();
    let Some(i) = parts.iter().position(|c| c.as_os_str() == "Cellar") else {
        return Vec::new();
    };
    let (Some(formula), Some(file)) = (parts.get(i + 1), exe.file_name()) else {
        return Vec::new();
    };
    let prefix: PathBuf = parts[..i].iter().collect();
    vec![
        prefix
            .join("opt")
            .join(formula.as_os_str())
            .join("bin")
            .join(file),
        prefix.join("bin").join(file),
    ]
}

/// A directory on the system PATH (and on `sudo`'s `secure_path`). Running
/// `tacitty enable`/`init` as root installs the binary here so `tacitty`
/// resolves in *every* root context — `sudo tacitty`, `su`, non-login shells
/// and an ssh `ProxyCommand` — not just an interactive shell that happens to
/// have `~/.local/bin` on PATH.
const SYSTEM_BIN_DIR: &str = "/usr/local/bin";

/// Is `dir` safe to install a root-executed binary into — i.e. `dir` and its
/// parent are both directories owned by root with no group/other write bit?
/// If a non-root user can write either one, they could swap the directory or
/// the binary we place in it and have root execute their code. This is the
/// real case on macOS/Homebrew-Intel, where `/usr/local` (and `/usr/local/bin`)
/// is owned by the admin *user*, not root — which this correctly rejects.
fn is_safe_system_dir(dir: &Path) -> bool {
    let root_owned_unwritable = |p: &Path| {
        matches!(
            fs::symlink_metadata(p),
            Ok(m) if m.file_type().is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0
        )
    };
    root_owned_unwritable(dir) && dir.parent().map_or(true, root_owned_unwritable)
}

/// Copy `exe` into `dir` as `tacitty` and return the installed path. The copy
/// is written to a temp file and renamed into place, so shells already
/// running the old copy are never handed a half-written file. The temp is
/// created with `O_CREAT|O_EXCL|O_NOFOLLOW` at mode `0755`, so a pre-planted
/// symlink or file at the temp path can't redirect or race the write (root
/// may be writing into a directory other users can see). The installed binary
/// is `0755`: other users may execute it, but it is owned by the installing
/// user and not writable by anyone else.
fn install_to(dir: &Path, exe: &Path) -> Result<PathBuf> {
    let target = dir.join("tacitty");
    if target.canonicalize().ok().as_deref() == Some(exe) {
        return Ok(target);
    }
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = dir.join(format!(".tacitty.tmp-{}", std::process::id()));
    let result = (|| -> Result<()> {
        let mut src = fs::File::open(exe).with_context(|| format!("opening {}", exe.display()))?;
        let mut dst = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        std::io::copy(&mut src, &mut dst)
            .and_then(|_| dst.sync_all())
            .with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, &target).with_context(|| format!("installing {}", target.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result?;
    Ok(target)
}

/// Make sure a stable copy of the running binary exists for the hook to
/// call, and return its path. Packaged installs (see
/// [`is_packaged_install`]) are used as-is; anything else (e.g. a binary
/// run from ~/Downloads) is copied to `~/.local/bin/tacitty`, so the hook
/// keeps working if the original is moved or deleted. For **root**, it is
/// copied to [`SYSTEM_BIN_DIR`] instead — but only when that directory is
/// safe ([`is_safe_system_dir`]) — so `tacitty` is on PATH in every root
/// context; an unsafe or unwritable system dir falls back to `~/.local/bin`
/// with a warning. (`/usr/local/bin` is itself a packaged path, so a later
/// run finds the binary already there and reuses it in place.)
pub fn install_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("locating the running tacitty binary")?;
    if is_packaged_install(&exe) {
        return Ok(stable_packaged_path(&exe)
            .into_iter()
            .find(|p| p.is_file())
            .unwrap_or(exe));
    }
    // Root: install to a system PATH dir so `tacitty` resolves everywhere —
    // but ONLY if that dir is safe (root-owned, not writable by other users).
    // Otherwise a non-root user could swap the binary and have root run it, so
    // fall back to ~/.local/bin (safe, but not on sudo's secure_path — warn).
    if crate::sys::geteuid() == 0 {
        let sysdir = Path::new(SYSTEM_BIN_DIR);
        if is_safe_system_dir(sysdir) {
            if let Ok(p) = install_to(sysdir, &exe) {
                return Ok(p);
            }
        }
        eprintln!(
            "tacitty: not installing to {SYSTEM_BIN_DIR} (missing, not root-owned, or writable \
             by others); using ~/.local/bin instead. `tacitty` may not be found under `sudo`/`su` \
             or in non-login shells — install it to a trusted system directory manually if you need that."
        );
    }
    install_to(&home()?.join(".local/bin"), &exe)
}

/// Rc files `enable` should hook: every supported shell whose rc file
/// already exists, plus the login shell's (created if missing), plus bash's
/// login-shell file (see [`bash_login_file`]). The last one matters on every
/// platform: a bash *login* shell — an ssh session, a console login, a macOS
/// terminal — reads `~/.bash_profile`/`~/.profile`, not `~/.bashrc`, so
/// without this an ssh user would have to run `tacitty shell` by hand.
fn target_files() -> Result<Vec<PathBuf>> {
    let login = login_shell();
    let mut out = Vec::new();
    for s in Shell::ALL {
        let rc = s.rc_path()?;
        if Some(s) == login || rc.exists() {
            out.push(rc);
        }
    }
    let file = bash_login_file()?;
    // ~/.profile is read by other shells (sh/dash) and display managers too:
    // only hook it when it is what the user's own bash login shell reads. A
    // bash-specific file (~/.bash_profile/~/.bash_login) is safe to hook when
    // it exists. The hook itself is guarded by `case $- in *i*` and `[ -t 0 ]`,
    // and when ~/.bashrc already runs the hook (and exits), the login file's
    // copy is never reached — so this never double-wraps.
    let bash_only = !file.ends_with(".profile");
    if (login == Some(Shell::Bash) || (bash_only && file.exists())) && !out.contains(&file) {
        out.push(file);
    }
    Ok(out)
}

/// Every file `enable` may have hooked, for `disable` and `doctor`.
fn hookable_files() -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for s in Shell::ALL {
        out.push(s.rc_path()?);
    }
    for name in BASH_LOGIN_FILES {
        out.push(home()?.join(name));
    }
    Ok(out)
}

/// What a bash login shell reads, in order of preference.
const BASH_LOGIN_FILES: [&str; 3] = [".bash_profile", ".bash_login", ".profile"];

/// The file a bash *login* shell runs: the first of [`BASH_LOGIN_FILES`]
/// that exists (bash reads only that one), or ~/.bash_profile if none does.
/// ssh sessions, console logins and macOS terminals all start login shells,
/// so there this, not ~/.bashrc, is what a new bash shell runs. Picking the
/// file bash already reads matters: creating ~/.bash_profile next to an
/// existing ~/.profile would stop bash from reading ~/.profile at all.
fn bash_login_file() -> Result<PathBuf> {
    Ok(bash_login_file_in(&home()?))
}

fn bash_login_file_in(home: &Path) -> PathBuf {
    BASH_LOGIN_FILES
        .iter()
        .map(|name| home.join(name))
        .find(|p| p.exists())
        .unwrap_or_else(|| home.join(".bash_profile"))
}

/// Replace `path` with `content` atomically: write a temporary file next
/// to it and rename it into place, so a crash or full disk can never leave
/// a half-written rc file. A symlinked rc file (dotfile managers) is
/// followed, and the real file is replaced, keeping its permissions.
fn write_rc(path: &Path, content: &str) -> Result<()> {
    let target = match fs::canonicalize(path) {
        Ok(real) => real,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Missing is fine (we create it), but a symlink pointing
            // nowhere is the user's setup; don't replace it with a file.
            if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
                bail!(
                    "{} is a symlink to a file that doesn't exist; fix or remove it and try again",
                    path.display()
                );
            }
            path.to_path_buf()
        }
        Err(e) => return Err(e).with_context(|| format!("resolving {}", path.display())),
    };
    let mode = match fs::metadata(&target) {
        Ok(m) => {
            // Rename would replace even a read-only or someone else's file;
            // refuse instead, as a normal in-place write would.
            if m.uid() != crate::sys::geteuid() {
                bail!("{} is not owned by you; not changing it", target.display());
            }
            if m.permissions().mode() & 0o200 == 0 {
                bail!("{} is read-only; not changing it", target.display());
            }
            m.permissions().mode() & 0o7777
        }
        Err(_) => 0o644,
    };
    let dir = target.parent().context("rc file has no parent directory")?;
    let name = target
        .file_name()
        .context("rc file has no name")?
        .to_string_lossy()
        .into_owned();
    let tmp = dir.join(format!(".{name}.tacitty-{}", std::process::id()));
    let result = (|| -> Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(content.as_bytes())
            .and_then(|_| f.sync_all())
            .with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, &target).with_context(|| format!("replacing {}", target.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn read_rc(path: &Path) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Install (or refresh) the hook. Returns the rc files that were written.
pub fn enable() -> Result<Vec<PathBuf>> {
    let files = target_files()?;
    if files.is_empty() {
        bail!(
            "auto-start supports bash and zsh, but $SHELL is {} and no ~/.bashrc or ~/.zshrc exists; \
             run `tacitty shell` manually or set your terminal's command to `tacitty shell`",
            std::env::var("SHELL").unwrap_or_else(|_| "unset".into())
        );
    }
    let bin = install_binary()?;
    let block = render_block(&bin);
    let mut written = Vec::new();
    for path in files {
        let before = read_rc(&path)?;
        let after = upsert_block(&before, &block);
        if after != before {
            write_rc(&path, &after)?;
        }
        written.push(path);
    }
    Ok(written)
}

/// Remove the hook from every rc file that has it. Returns those files.
pub fn disable() -> Result<Vec<PathBuf>> {
    let mut removed = Vec::new();
    for path in hookable_files()? {
        if let Some(after) = remove_block(&read_rc(&path)?) {
            write_rc(&path, &after)?;
            removed.push(path);
        }
    }
    Ok(removed)
}

/// Rc files that currently contain the hook.
pub fn enabled_in() -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for path in hookable_files()? {
        if has_block(&read_rc(&path)?) {
            out.push(path);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block() -> String {
        render_block(Path::new("/home/u/.local/bin/tacitty"))
    }

    #[test]
    fn append_then_remove_round_trips() {
        let original = "export FOO=1\nalias ll='ls -l'\n";
        let with = upsert_block(original, &block());
        assert!(with.starts_with(original));
        assert!(has_block(&with));
        assert_eq!(remove_block(&with).unwrap(), original);
    }

    #[test]
    fn append_to_file_without_trailing_newline() {
        let with = upsert_block("export FOO=1", &block());
        assert!(with.starts_with("export FOO=1\n\n# >>> tacitty"));
        assert_eq!(remove_block(&with).unwrap(), "export FOO=1\n");
    }

    #[test]
    fn upsert_is_idempotent_and_replaces_in_place() {
        let once = upsert_block("a\n", &block());
        assert_eq!(upsert_block(&once, &block()), once);

        let moved = render_block(Path::new("/opt/tacitty/bin/tacitty"));
        let with_tail = format!("{once}after\n");
        let replaced = upsert_block(&with_tail, &moved);
        assert!(replaced.contains("/opt/tacitty/bin/tacitty"));
        assert!(!replaced.contains("/home/u/.local/bin/tacitty"));
        assert!(replaced.ends_with("after\n"));
        assert_eq!(replaced.matches(BEGIN_MARKER).count(), 1);
    }

    #[test]
    fn remove_without_block_is_none() {
        assert!(remove_block("export FOO=1\n").is_none());
        assert!(remove_block("").is_none());
    }

    #[test]
    fn empty_rc_gets_just_the_block() {
        assert_eq!(upsert_block("", &block()), block());
        assert_eq!(remove_block(&block()).unwrap(), "");
    }

    #[test]
    fn packaged_installs_are_used_in_place() {
        for p in [
            "/usr/bin/tacitty",
            "/opt/tacitty/bin/tacitty",
            "/opt/homebrew/Cellar/tacitty/0.1.0/bin/tacitty",
            "/usr/local/Cellar/tacitty/0.1.0/bin/tacitty",
            "/opt/local/bin/tacitty",
        ] {
            assert!(is_packaged_install(Path::new(p)), "{p}");
        }
        for p in [
            "/home/u/.local/bin/tacitty",
            "/Users/u/.local/bin/tacitty",
            "/Users/u/Downloads/tacitty",
        ] {
            assert!(!is_packaged_install(Path::new(p)), "{p}");
        }
    }

    #[test]
    fn block_quotes_path_and_uses_fallback_code() {
        let b = render_block(Path::new("/home/o'brien/bin/tacitty"));
        assert!(b.contains(r"'/home/o'\''brien/bin/tacitty' shell --autostart"));
        assert!(b.contains(&format!("-ne {FALLBACK_EXIT_CODE}")));
        assert!(b.contains("NO_TACITTY"));
        assert!(b.contains("TACITTY_ACTIVE"));
    }

    #[test]
    fn system_bin_dir_is_on_secure_path_and_reused_in_place() {
        assert_eq!(SYSTEM_BIN_DIR, "/usr/local/bin");
        // The root dir is itself a "packaged" path, so a later enable finds
        // the binary already installed and reuses it in place (idempotent).
        assert!(is_packaged_install(
            &PathBuf::from(SYSTEM_BIN_DIR).join("tacitty")
        ));
    }

    #[test]
    fn system_dir_safety_rejects_non_root_owned_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        // A path that doesn't exist is never "safe".
        assert!(!is_safe_system_dir(&dir.path().join("nope")));
        // A directory owned by the (non-root) test user must be rejected —
        // this is the macOS/Homebrew-Intel `/usr/local` case.
        if crate::sys::geteuid() != 0 {
            let sub = dir.path().join("bin");
            std::fs::create_dir(&sub).unwrap();
            assert!(!is_safe_system_dir(&sub));
        }
    }

    #[test]
    fn bash_login_file_prefers_the_file_bash_actually_reads() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        // Nothing present yet → default to ~/.bash_profile (what we'd create).
        assert_eq!(bash_login_file_in(home), home.join(".bash_profile"));
        // ~/.profile alone → that's what a login bash reads.
        std::fs::write(home.join(".profile"), "").unwrap();
        assert_eq!(bash_login_file_in(home), home.join(".profile"));
        // ~/.bash_profile shadows ~/.profile for bash login shells.
        std::fs::write(home.join(".bash_profile"), "").unwrap();
        assert_eq!(bash_login_file_in(home), home.join(".bash_profile"));
    }

    #[test]
    fn homebrew_cellar_paths_map_to_stable_links() {
        let exe = Path::new("/opt/homebrew/Cellar/tacitty/0.1.0/bin/tacitty");
        assert_eq!(
            stable_packaged_path(exe),
            vec![
                PathBuf::from("/opt/homebrew/opt/tacitty/bin/tacitty"),
                PathBuf::from("/opt/homebrew/bin/tacitty"),
            ]
        );
        let intel = Path::new("/usr/local/Cellar/tacitty/0.2.0/bin/tacitty");
        assert_eq!(
            stable_packaged_path(intel)[0],
            PathBuf::from("/usr/local/opt/tacitty/bin/tacitty")
        );
        assert!(stable_packaged_path(Path::new("/usr/bin/tacitty")).is_empty());
    }
}
