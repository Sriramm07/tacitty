//! Local secret-prompt detection (spec §6.1) and alternate-screen tracking.

use std::os::fd::RawFd;

use crate::sys;

/// `!ECHO && (ICANON || ECHONL)` on the pty master's termios — the same
/// heuristic used by Ghostty and ghostel.
pub fn is_secret_termios(t: &libc::termios) -> bool {
    let echo_off = t.c_lflag & libc::ECHO == 0;
    let canon_ish = (t.c_lflag & libc::ICANON != 0) || (t.c_lflag & libc::ECHONL != 0);
    echo_off && canon_ish
}

pub fn read_secret_mode(master_fd: RawFd) -> bool {
    match sys::tcgetattr(master_fd) {
        Ok(t) => is_secret_termios(&t),
        Err(_) => false,
    }
}

/// Tracks whether the child currently has the terminal's alternate screen
/// buffer active (`ESC[?1049h` / `?47h` / `?1047h` ... `l`), by scanning
/// output bytes for those specific DEC private-mode sequences. Anything more
/// (full VTE emulation) is unnecessary: we only need this one bit.
#[derive(Default)]
pub struct AltScreenTracker {
    active: bool,
    // small rolling buffer to catch sequences split across read() calls
    tail: Vec<u8>,
}

const NEEDLES_ON: [&[u8]; 3] = [b"\x1b[?1049h", b"\x1b[?47h", b"\x1b[?1047h"];
const NEEDLES_OFF: [&[u8]; 3] = [b"\x1b[?1049l", b"\x1b[?47l", b"\x1b[?1047l"];
const MAX_NEEDLE: usize = 8;

impl AltScreenTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn feed(&mut self, chunk: &[u8]) {
        self.tail.extend_from_slice(chunk);
        let mut i = 0;
        while i < self.tail.len() {
            let rest = &self.tail[i..];
            if NEEDLES_ON.iter().any(|n| rest.starts_with(n)) {
                self.active = true;
                i += 8;
                continue;
            }
            if NEEDLES_OFF.iter().any(|n| rest.starts_with(n)) {
                self.active = false;
                i += 8;
                continue;
            }
            i += 1;
        }
        if self.tail.len() > MAX_NEEDLE * 4 {
            let cut = self.tail.len() - (MAX_NEEDLE - 1);
            self.tail.drain(..cut);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(lflag: libc::tcflag_t) -> libc::termios {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        t.c_lflag = lflag;
        t
    }

    #[test]
    fn sudo_like_is_secret() {
        assert!(is_secret_termios(&t(libc::ICANON)));
    }

    #[test]
    fn normal_shell_is_not_secret() {
        assert!(!is_secret_termios(&t(libc::ICANON | libc::ECHO)));
    }

    #[test]
    fn raw_editor_is_not_secret() {
        assert!(!is_secret_termios(&t(0)));
    }

    #[test]
    fn echonl_variant_counts() {
        assert!(is_secret_termios(&t(libc::ECHONL)));
    }

    #[test]
    fn alt_screen_toggle() {
        let mut a = AltScreenTracker::new();
        assert!(!a.is_active());
        a.feed(b"hello \x1b[?1049h world");
        assert!(a.is_active());
        a.feed(b"more \x1b[?1049l text");
        assert!(!a.is_active());
    }

    #[test]
    fn alt_screen_split_across_reads() {
        let mut a = AltScreenTracker::new();
        a.feed(b"abc\x1b[?10");
        assert!(!a.is_active());
        a.feed(b"49h");
        assert!(a.is_active());
    }

    #[test]
    fn alt_screen_variants() {
        for on in NEEDLES_ON {
            let mut a = AltScreenTracker::new();
            a.feed(on);
            assert!(a.is_active());
        }
    }

    #[test]
    fn alt_screen_tracker_never_panics_or_grows_unbounded() {
        // Stable-Rust stand-in for the nightly-only `alt_screen_tracker`
        // fuzz target -- see the note in src/statemachine.rs for what
        // this can and can't substitute for.
        struct Rng(u64);
        impl Rng {
            fn next_u64(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x.wrapping_mul(0x2545_f491_4f6c_dd1d)
            }
        }

        let mut rng = Rng(0xC0FF_EE00_u64);
        let mut tracker = AltScreenTracker::new();
        for _ in 0..300_000 {
            let len = (rng.next_u64() % 32) as usize;
            let mut chunk = vec![0u8; len];
            for b in chunk.iter_mut() {
                // Bias toward ESC and '[' so real escape-sequence prefixes
                // actually get constructed sometimes, not just uniform noise.
                *b = match rng.next_u64() % 6 {
                    0 => 0x1b,
                    1 => b'[',
                    2 => b'?',
                    _ => (rng.next_u64() & 0x7f) as u8,
                };
            }
            tracker.feed(&chunk);
            assert!(
                tracker.tail.len() <= MAX_NEEDLE * 4,
                "internal buffer grew unbounded: {} bytes",
                tracker.tail.len()
            );
            let _ = tracker.is_active();
        }
    }
}
