//! `tacitty update`: replace the running binary with the latest GitHub
//! release, the same way `install.sh` installs it.
//!
//! Downloads go through `curl` (or `wget`) and unpacking through `tar`,
//! exactly as `install.sh` does, rather than pulling an HTTP/TLS stack and
//! archive crates into the dependency tree for one rarely used command.
//! Every child process is spawned directly (never through a shell). The
//! tarball is verified against its published SHA-256 before anything is
//! unpacked, and the new binary must run and report the expected version
//! before it is renamed over the old one.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

const DEFAULT_RELEASES_URL: &str = "https://github.com/Sriramm07/tacitty/releases";

/// `TACITTY_RELEASES_URL`, honoured only in builds with the `test-hooks`
/// feature (the integration tests point it at a local server). In every
/// normal build an environment variable can't redirect updates.
fn releases_url_override() -> Option<String> {
    if !cfg!(feature = "test-hooks") {
        return None;
    }
    std::env::var("TACITTY_RELEASES_URL")
        .ok()
        .filter(|u| !u.is_empty())
}

fn releases_url() -> String {
    releases_url_override().unwrap_or_else(|| DEFAULT_RELEASES_URL.to_string())
}

/// Downloads must stay on HTTPS, including across redirects, except when a
/// test build points at a local server.
fn https_only() -> bool {
    releases_url_override().is_none()
}

/// The release target triple for this machine's prebuilt binary.
pub fn target_triple() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("x86_64-unknown-linux-musl"),
        "aarch64" => Ok("aarch64-unknown-linux-musl"),
        other => bail!("no prebuilt release for {other}; update by rebuilding from source"),
    }
}

/// Parse `X.Y.Z` (an optional leading `v` and any `-pre`/`+build` suffix
/// are ignored) into a comparable tuple.
pub fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().strip_prefix('v').unwrap_or(s.trim());
    let core = s.split(['-', '+']).next()?;
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    let v = (it.next()??, it.next()??, it.next()??);
    if it.next().is_some() {
        return None;
    }
    Some(v)
}

/// Extract the tag from the URL `/releases/latest` redirects to
/// (`.../releases/tag/v1.2.3`).
pub fn tag_from_url(url: &str) -> Option<&str> {
    let tag = url.trim().rsplit_once("/tag/")?.1.trim_end_matches('/');
    (!tag.is_empty() && !tag.contains('/')).then_some(tag)
}

/// The hex digest from a `sha256sum`-style line (`<hex>  <file>`).
pub fn parse_checksum(line: &str) -> Option<String> {
    let hex = line.split_whitespace().next()?.to_ascii_lowercase();
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then_some(hex)
}

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn asset_name(tag: &str, target: &str) -> String {
    format!("tacitty-{tag}-{target}")
}

enum Fetcher {
    Curl,
    Wget,
}

impl Fetcher {
    fn detect() -> Result<Fetcher> {
        if on_path("curl") {
            Ok(Fetcher::Curl)
        } else if on_path("wget") {
            Ok(Fetcher::Wget)
        } else {
            bail!("`tacitty update` needs curl or wget")
        }
    }

    /// Download `url` to `dest`.
    fn get(&self, url: &str, dest: &Path) -> Result<()> {
        let mut cmd = match self {
            Fetcher::Curl => {
                let mut c = Command::new("curl");
                if https_only() {
                    c.args(["--proto", "=https", "--proto-redir", "=https"]);
                }
                c.args(["-fsSL", "-o"]).arg(dest).arg(url);
                c
            }
            Fetcher::Wget => {
                let mut c = Command::new("wget");
                if https_only() {
                    c.arg("--https-only");
                }
                c.args(["-q", "-O"]).arg(dest).arg(url);
                c
            }
        };
        let status = cmd
            .stdin(Stdio::null())
            .status()
            .context("running the downloader")?;
        if !status.success() {
            bail!("download failed: {url}");
        }
        Ok(())
    }

    /// The URL `url` finally redirects to.
    fn final_url(&self, url: &str) -> Result<String> {
        let out = match self {
            Fetcher::Curl => {
                let mut c = Command::new("curl");
                if https_only() {
                    c.args(["--proto", "=https", "--proto-redir", "=https"]);
                }
                c.args(["-fsSLI", "-o", "/dev/null", "-w", "%{url_effective}", url])
                    .stdin(Stdio::null())
                    .output()
            }
            Fetcher::Wget => {
                let mut c = Command::new("wget");
                if https_only() {
                    c.arg("--https-only");
                }
                c.args(["-q", "-S", "--spider", url])
                    .stdin(Stdio::null())
                    .output()
            }
        }
        .context("running the downloader")?;
        if !out.status.success() {
            bail!("could not reach {url}");
        }
        Ok(match self {
            Fetcher::Curl => String::from_utf8_lossy(&out.stdout).into_owned(),
            // wget prints response headers on stderr; the last Location wins.
            Fetcher::Wget => String::from_utf8_lossy(&out.stderr)
                .lines()
                .rev()
                .find_map(|l| {
                    let l = l.trim();
                    l.get(..9)
                        .filter(|p| p.eq_ignore_ascii_case("location:"))
                        .map(|_| l[9..].trim().to_string())
                })
                .unwrap_or_default(),
        })
    }
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

/// What `update` did.
pub enum Outcome {
    UpToDate {
        current: String,
    },
    Available {
        current: String,
        latest: String,
    },
    Updated {
        from: String,
        to: String,
        path: PathBuf,
    },
}

/// Check for (and unless `check_only`, install) the latest release.
pub fn run(check_only: bool) -> Result<Outcome> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let fetcher = Fetcher::detect()?;
    let base = releases_url();

    let redirected = fetcher.final_url(&format!("{base}/latest"))?;
    let tag = tag_from_url(&redirected)
        .with_context(|| format!("could not find the latest release (got {redirected:?})"))?
        .to_string();
    let latest = parse_version(&tag).with_context(|| format!("unexpected release tag {tag:?}"))?;
    let cur = parse_version(&current).context("unparseable built-in version")?;

    if latest <= cur {
        return Ok(Outcome::UpToDate { current });
    }
    let latest_str = tag.trim_start_matches('v').to_string();
    if check_only {
        return Ok(Outcome::Available {
            current,
            latest: latest_str,
        });
    }

    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("locating the running tacitty binary")?;
    let dir = exe.parent().context("binary has no parent directory")?;
    if exe.starts_with("/usr") || exe.starts_with("/opt") {
        bail!(
            "{} looks like a system-managed install; update it with your package manager, \
             or reinstall with install.sh",
            exe.display()
        );
    }

    let target = target_triple()?;
    let name = asset_name(&tag, target);
    let work = tempdir_in(&std::env::temp_dir())?;
    let result = (|| -> Result<PathBuf> {
        let tarball = work.join(format!("{name}.tar.gz"));
        let sumfile = work.join(format!("{name}.tar.gz.sha256"));
        fetcher.get(&format!("{base}/download/{tag}/{name}.tar.gz"), &tarball)?;
        fetcher.get(
            &format!("{base}/download/{tag}/{name}.tar.gz.sha256"),
            &sumfile,
        )?;

        let expected =
            parse_checksum(&fs::read_to_string(&sumfile)?).context("malformed checksum file")?;
        let actual = sha256_hex(&fs::read(&tarball)?);
        if expected != actual {
            bail!("checksum mismatch (expected {expected}, got {actual}); nothing was changed");
        }

        let status = Command::new("tar")
            .arg("-xzf")
            .arg(&tarball)
            .arg("-C")
            .arg(&work)
            .arg(format!("{name}/tacitty"))
            .stdin(Stdio::null())
            .status()
            .context("running tar")?;
        if !status.success() {
            bail!("could not unpack {name}.tar.gz");
        }

        // Stage next to the old binary so the final rename is atomic (same
        // filesystem), and refuse to swap in anything that doesn't run.
        // A fresh random name, created exclusively and without following
        // symlinks, so nothing else can be waiting at that path.
        let staged = dir.join(format!(".tacitty.update-{}", random_hex(8)?));
        {
            let mut src = fs::File::open(work.join(&name).join("tacitty"))
                .context("opening the unpacked binary")?;
            let mut dst = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o755)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&staged)
                .with_context(|| format!("writing {} (is it writable?)", staged.display()))?;
            if let Err(e) = std::io::copy(&mut src, &mut dst).and_then(|_| dst.sync_all()) {
                let _ = fs::remove_file(&staged);
                return Err(e).context("writing the new binary");
            }
        }
        let out = Command::new(&staged)
            .arg("--version")
            .stdin(Stdio::null())
            .output();
        let reported = out
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        if !reported.split_whitespace().any(|w| w == latest_str) {
            let _ = fs::remove_file(&staged);
            bail!("downloaded binary failed its self-check; nothing was changed");
        }
        if let Err(e) = fs::rename(&staged, &exe) {
            let _ = fs::remove_file(&staged);
            return Err(e).with_context(|| format!("replacing {}", exe.display()));
        }
        Ok(exe.clone())
    })();
    let _ = fs::remove_dir_all(&work);

    Ok(Outcome::Updated {
        from: current,
        to: latest_str,
        path: result?,
    })
}

fn random_hex(bytes: usize) -> Result<String> {
    let mut rnd = vec![0u8; bytes];
    crate::sys::getrandom(&mut rnd)?;
    Ok(rnd.iter().map(|b| format!("{b:02x}")).collect())
}

/// A fresh private directory under `parent`.
fn tempdir_in(parent: &Path) -> Result<PathBuf> {
    let dir = parent.join(format!("tacitty-update-{}", random_hex(8)?));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_and_compare() {
        assert_eq!(parse_version("v0.1.0"), Some((0, 1, 0)));
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("v1.2.3-rc.1"), Some((1, 2, 3)));
        assert_eq!(parse_version("1.10.0+build5"), Some((1, 10, 0)));
        assert!(parse_version("v1.10.0") > parse_version("v1.9.9"));
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_version("latest"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn tag_comes_from_redirect_url() {
        assert_eq!(
            tag_from_url("https://github.com/Sriramm07/tacitty/releases/tag/v0.2.0"),
            Some("v0.2.0")
        );
        assert_eq!(
            tag_from_url("https://x/releases/tag/v0.2.0/\n"),
            Some("v0.2.0")
        );
        // No releases yet: GitHub leaves you on /releases.
        assert_eq!(
            tag_from_url("https://github.com/Sriramm07/tacitty/releases"),
            None
        );
        assert_eq!(tag_from_url("https://x/releases/tag/"), None);
    }

    #[test]
    fn checksum_lines() {
        let hex = "0d3ee177e183c9eb39302c43e016d249250949624437a94b6a9020442e3837f4";
        assert_eq!(
            parse_checksum(&format!("{hex}  file.tar.gz\n")).as_deref(),
            Some(hex)
        );
        assert_eq!(
            parse_checksum(&hex.to_uppercase()).as_deref(),
            Some(hex),
            "uppercase is normalised"
        );
        assert_eq!(parse_checksum("abc123  file"), None);
        assert_eq!(parse_checksum(""), None);
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn asset_names_match_release_workflow() {
        assert_eq!(
            asset_name("v0.1.0", "x86_64-unknown-linux-musl"),
            "tacitty-v0.1.0-x86_64-unknown-linux-musl"
        );
    }
}
