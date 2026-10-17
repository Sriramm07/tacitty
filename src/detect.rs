//! Local secret-prompt detection (spec §6.1) and alternate-screen tracking.

use std::os::fd::RawFd;

use crate::sys;

/// `!ECHO && (ICANON || ECHONL)` on the pty master's termios: input is
/// hidden, but still read a line at a time (how password prompts read), as
/// opposed to raw mode (how editors and full-screen programs read).
pub fn is_secret_termios(t: &libc::termios) -> bool {
    let echo_off = t.c_lflag & libc::ECHO == 0;
    let canon_ish = (t.c_lflag & libc::ICANON != 0) || (t.c_lflag & libc::ECHONL != 0);
    echo_off && canon_ish
}

/// Is the program on the other side of the pty reading a password right
/// now? `tcgetattr` on the master reports the slave's settings on both
/// Linux and macOS (see [`sys::Pty`]).
pub fn read_secret_mode(master_fd: RawFd) -> bool {
    match sys::tcgetattr(master_fd) {
        Ok(t) => is_secret_termios(&t),
        Err(_) => false,
    }
}

/// Tracks whether the child currently has the terminal's alternate screen
/// buffer active (DEC private modes 1049 / 1047 / 47, set with
/// `ESC [ ? <params> h` and reset with `... l`). A small byte-level parser
/// handles combined parameters (`ESC[?1049;2004h`), back-to-back sequences
/// and sequences split across reads. Anything more (full VTE emulation) is
/// unnecessary: we only need this one bit.
#[derive(Default)]
pub struct AltScreenTracker {
    active: bool,
    state: AltState,
    params: Vec<u16>,
    current: Option<u16>,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum AltState {
    #[default]
    Ground,
    Esc,
    Csi,
    PrivateParams,
}

/// More parameters than any real sequence uses; beyond this we give up on
/// the sequence rather than grow without bound.
const MAX_PARAMS: usize = 16;

impl AltScreenTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn feed(&mut self, chunk: &[u8]) {
        for &b in chunk {
            self.step(b);
        }
    }

    fn step(&mut self, b: u8) {
        match self.state {
            AltState::Ground => {
                if b == 0x1b {
                    self.state = AltState::Esc;
                }
            }
            AltState::Esc => {
                self.state = if b == b'[' {
                    AltState::Csi
                } else if b == 0x1b {
                    AltState::Esc
                } else {
                    AltState::Ground
                };
            }
            AltState::Csi => {
                if b == b'?' {
                    self.params.clear();
                    self.current = None;
                    self.state = AltState::PrivateParams;
                } else {
                    self.state = if b == 0x1b {
                        AltState::Esc
                    } else {
                        AltState::Ground
                    };
                }
            }
            AltState::PrivateParams => match b {
                b'0'..=b'9' => {
                    let d = u16::from(b - b'0');
                    self.current = Some(
                        self.current
                            .unwrap_or(0)
                            .saturating_mul(10)
                            .saturating_add(d),
                    );
                }
                b';' => {
                    if self.params.len() < MAX_PARAMS {
                        self.params.push(self.current.take().unwrap_or(0));
                    } else {
                        self.state = AltState::Ground;
                    }
                }
                b'h' | b'l' => {
                    if let Some(p) = self.current.take() {
                        self.params.push(p);
                    }
                    if self.params.iter().any(|p| matches!(p, 1049 | 1047 | 47)) {
                        self.active = b == b'h';
                    }
                    self.state = AltState::Ground;
                }
                0x1b => self.state = AltState::Esc,
                _ => self.state = AltState::Ground,
            },
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
        for on in [
            &b"\x1b[?1049h"[..],
            b"\x1b[?47h",
            b"\x1b[?1047h",
            b"\x1b[?2004;1049h",
        ] {
            let mut a = AltScreenTracker::new();
            a.feed(on);
            assert!(a.is_active(), "{on:?}");
        }
        // Other private modes don't count.
        let mut a = AltScreenTracker::new();
        a.feed(b"\x1b[?2004h\x1b[?25l\x1b[?104h");
        assert!(!a.is_active());
    }

    #[test]
    fn back_to_back_toggles_are_all_seen() {
        let mut a = AltScreenTracker::new();
        a.feed(b"\x1b[?47h\x1b[?47l");
        assert!(!a.is_active());
        a.feed(b"\x1b[?47l\x1b[?1049h");
        assert!(a.is_active());
        a.feed(b"\x1b[?1049;2004l");
        assert!(!a.is_active());
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
                tracker.params.len() <= MAX_PARAMS,
                "parameter buffer grew unbounded: {}",
                tracker.params.len()
            );
            let _ = tracker.is_active();
        }
    }
}
