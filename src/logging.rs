//! Minimal, leak-proof logging.
//!
//! `TACITTY_LOG=/path/to/file` enables logging. The only entry point takes a
//! `&'static str`, so it is *structurally impossible* to log input bytes,
//! buffer contents, aliases or secrets: only fixed state-transition labels.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static LOG: OnceLock<Mutex<Option<File>>> = OnceLock::new();

fn sink() -> &'static Mutex<Option<File>> {
    LOG.get_or_init(|| {
        let f = std::env::var_os("TACITTY_LOG").and_then(|p| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(p)
                .ok()
        });
        Mutex::new(f)
    })
}

/// Log a fixed state-transition label.
pub fn event(label: &'static str) {
    if let Ok(mut g) = sink().lock() {
        if let Some(f) = g.as_mut() {
            let t = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            let _ = writeln!(f, "{t} {label}");
        }
    }
}
