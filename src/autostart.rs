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
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
  if [ -z \"${{TACITTY_ACTIVE:-}}\" ] && [ -z \"${{NO_TACITTY:-}}\" ] && [ -t 0 ] && [ -x {bin} ]; then
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

/// Make sure a stable copy of the running binary exists for the hook to
/// call, and return its path. Packaged installs (`/usr`, `/opt`) are used
/// as-is; anything else (e.g. a binary run from ~/Downloads) is copied to
/// `~/.local/bin/tacitty`, so the hook keeps working if the original is
/// moved or deleted.
pub fn install_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("locating the running tacitty binary")?;
    if exe.starts_with("/usr") || exe.starts_with("/opt") {
        return Ok(exe);
    }
    let dir = home()?.join(".local/bin");
    let target = dir.join("tacitty");
    if target.canonicalize().ok().as_deref() == Some(exe.as_path()) {
        return Ok(target);
    }
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    // Copy to a temp name and rename over the target, so shells already
    // running the old copy are never handed a half-written file.
    let tmp = dir.join(format!(".tacitty.tmp-{}", std::process::id()));
    fs::copy(&exe, &tmp).with_context(|| format!("copying binary to {}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
    fs::rename(&tmp, &target).with_context(|| format!("installing {}", target.display()))?;
    Ok(target)
}

/// Rc files `enable` should hook: every supported shell whose rc file
/// already exists, plus the login shell's (created if missing).
fn target_shells() -> Result<Vec<Shell>> {
    let login = login_shell();
    let mut out = Vec::new();
    for s in Shell::ALL {
        if Some(s) == login || s.rc_path()?.exists() {
            out.push(s);
        }
    }
    Ok(out)
}

/// Write `content` to `path` in place (following symlinks, so dotfile
/// managers keep working), creating it 0644 if it doesn't exist yet.
fn write_rc(path: &Path, content: &str) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    f.write_all(content.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
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
    let shells = target_shells()?;
    if shells.is_empty() {
        bail!(
            "auto-start supports bash and zsh, but $SHELL is {} and no ~/.bashrc or ~/.zshrc exists; \
             run `tacitty shell` manually or set your terminal's command to `tacitty shell`",
            std::env::var("SHELL").unwrap_or_else(|_| "unset".into())
        );
    }
    let bin = install_binary()?;
    let block = render_block(&bin);
    let mut written = Vec::new();
    for s in shells {
        let path = s.rc_path()?;
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
    for s in Shell::ALL {
        let path = s.rc_path()?;
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
    for s in Shell::ALL {
        let path = s.rc_path()?;
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
    fn block_quotes_path_and_uses_fallback_code() {
        let b = render_block(Path::new("/home/o'brien/bin/tacitty"));
        assert!(b.contains(r"'/home/o'\''brien/bin/tacitty' shell --autostart"));
        assert!(b.contains(&format!("-ne {FALLBACK_EXIT_CODE}")));
        assert!(b.contains("NO_TACITTY"));
        assert!(b.contains("TACITTY_ACTIVE"));
    }
}
