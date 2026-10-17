//! Remote-prompt fallback (spec §6.2): when the local pty is raw (an ssh/
//! mosh/telnet/docker/kubectl/podman client controls it) we can't see the
//! remote host's termios, so we watch the *output* instead.

use std::collections::VecDeque;

use regex::Regex;
use vte::{Params, Parser, Perform};

/// Tracks the plain text on the current output line (escape sequences
/// stripped) by feeding output bytes through a `vte` parser.
pub struct LineTracker {
    parser: Parser,
    perform: LinePerform,
}

struct LinePerform {
    /// The last `max_chars` characters (characters, not bytes: trimming a
    /// `String` by byte count can split a multi-byte character and panic).
    /// Kept as a ring buffer so each printed character is O(1); the text is
    /// only assembled when someone asks for it.
    chars: VecDeque<char>,
    max_chars: usize,
}

impl LinePerform {
    fn clear(&mut self) {
        self.chars.clear();
    }
}

// Any control, escape or CSI sequence that moves the cursor, erases or
// scrolls means the line on screen is no longer simply "what was printed
// since the last newline". Each of these forgets the tracked line rather
// than guess: a missed remote prompt is safe, a false one is not.
impl Perform for LinePerform {
    fn print(&mut self, c: char) {
        if self.chars.len() == self.max_chars {
            self.chars.pop_front();
        }
        self.chars.push_back(c);
    }

    fn execute(&mut self, byte: u8) {
        // LF, VT, FF, CR, backspace.
        if matches!(byte, b'\n' | 0x0b | 0x0c | b'\r' | 0x08) {
            self.clear();
        }
    }

    fn csi_dispatch(
        &mut self,
        _params: &Params,
        _intermediates: &[u8],
        _ignore: bool,
        action: char,
    ) {
        if matches!(
            action,
            'A' | 'B'
                | 'C'
                | 'D'
                | 'E'
                | 'F'
                | 'G'
                | 'H'
                | 'J'
                | 'K'
                | 'L'
                | 'M'
                | 'P'
                | 'S'
                | 'T'
                | 'X'
                | '@'
                | '`'
                | 'a'
                | 'd'
                | 'e'
                | 'f'
                | 'u'
        ) {
            self.clear();
        }
    }

    fn esc_dispatch(&mut self, intermediates: &[u8], _ignore: bool, byte: u8) {
        // ESC 8 (restore cursor), ESC D / E / M (index, next line, reverse
        // index), ESC c (full reset).
        if intermediates.is_empty() && matches!(byte, b'8' | b'D' | b'E' | b'M' | b'c') {
            self.clear();
        }
    }
}

impl LineTracker {
    pub fn new() -> Self {
        LineTracker {
            parser: Parser::new(),
            perform: LinePerform {
                chars: VecDeque::with_capacity(512),
                max_chars: 512,
            },
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.parser.advance(&mut self.perform, bytes);
    }

    /// The plain text of the output since the last newline (at most the
    /// last 512 characters).
    pub fn current_line(&self) -> String {
        self.perform.chars.iter().collect()
    }
}

impl Default for LineTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Does the current line look like a remote password prompt?
pub fn looks_like_prompt(re: &Regex, line: &str) -> bool {
    re.is_match(line)
}

/// Small ring buffer recording the last few foreground-process names seen,
/// purely for `tacitty doctor` diagnostics.
pub struct RecentNames {
    buf: VecDeque<String>,
    cap: usize,
}

impl RecentNames {
    pub fn new(cap: usize) -> Self {
        RecentNames {
            buf: VecDeque::with_capacity(cap),
            cap,
        }
    }

    pub fn push(&mut self, name: String) {
        if self.buf.back() == Some(&name) {
            return;
        }
        if self.buf.len() == self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back(name);
    }
}

/// Read `/proc/<pid>/comm` (trimmed), if it exists.
#[cfg(target_os = "linux")]
pub fn proc_comm(pid: i32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// The process's short name (`p_comm`), macOS's equivalent of
/// `/proc/<pid>/comm`.
#[cfg(target_os = "macos")]
pub fn proc_comm(pid: i32) -> Option<String> {
    crate::sys::proc_comm(pid)
}

/// Is `comm` in the configured allowlist of remote-fallback-eligible
/// process names?
pub fn is_allowlisted(comm: &str, allowlist: &[String]) -> bool {
    allowlist.iter().any(|a| a == comm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_plain_line_across_writes() {
        let mut lt = LineTracker::new();
        lt.feed(b"Last login: Tue\n");
        lt.feed(b"[user@host ~]$ sudo systemctl restart nginx\n");
        lt.feed(b"[sudo] password for user: ");
        assert_eq!(lt.current_line(), "[sudo] password for user: ");
    }

    #[test]
    fn strips_ansi_colors() {
        let mut lt = LineTracker::new();
        lt.feed(b"\x1b[1;32muser@host\x1b[0m:~$ ");
        assert_eq!(lt.current_line(), "user@host:~$ ");
    }

    #[test]
    fn prompt_regex_matches_common_forms() {
        let re = crate::config::Config::default().prompt_regex();
        for line in [
            "Password: ",
            "[sudo] password for sriram: ",
            "Password for user postgres: ",
            "admin@10.42.0.15's password: ",
            "Enter passphrase for key '/home/sriram/.ssh/id_ed25519': ",
            "PIN: ",
            "Enter PIN for 'token': ",
        ] {
            assert!(looks_like_prompt(&re, line), "{line:?}");
        }
        for line in [
            "$ ",
            "Permission denied",
            "password changed successfully",
            // "pin" inside other words must not count.
            "Shipping address: ",
            "Stopping: ",
            "Mapping name: ",
            "Opinion: ",
        ] {
            assert!(!looks_like_prompt(&re, line), "{line:?}");
        }
    }

    #[test]
    fn long_multibyte_lines_never_panic() {
        let mut lt = LineTracker::new();
        let mut line = "é".repeat(700).into_bytes();
        line.extend_from_slice("日本語".repeat(300).as_bytes());
        lt.feed(&line);
        assert_eq!(lt.current_line().chars().count(), 512);
        lt.feed(b"\nPassword: ");
        assert_eq!(lt.current_line(), "Password: ");
    }

    #[test]
    fn cursor_movement_and_erase_forget_the_line() {
        let mut lt = LineTracker::new();
        lt.feed(b"Password: ");
        lt.feed(b"\x1b[2K");
        assert_eq!(lt.current_line(), "");
        lt.feed(b"Password: \x1b[10G");
        assert_eq!(lt.current_line(), "");
        lt.feed(b"Password: \x08");
        assert_eq!(lt.current_line(), "");
        for seq in [
            &b"\x1b8"[..],
            b"\x1bM",
            b"\x1bD",
            b"\x1bE",
            b"\x1bc",
            b"\x1b[2L",
            b"\x1b[M",
            b"\x1b[S",
            b"\x1b[T",
            b"\x1b[5`",
            b"\x1b[3a",
            b"\x1b[e",
            b"\x0b",
            b"\x0c",
        ] {
            lt.feed(b"Password: ");
            lt.feed(seq);
            assert_eq!(lt.current_line(), "", "{seq:?}");
        }
        // Colours and other attributes don't move the cursor.
        lt.feed(b"\x1b[1mPassword:\x1b[0m ");
        assert_eq!(lt.current_line(), "Password: ");
    }

    #[test]
    fn very_long_lines_stay_fast() {
        let mut lt = LineTracker::new();
        let chunk = vec![b'x'; 1 << 20];
        let start = std::time::Instant::now();
        for _ in 0..10 {
            lt.feed(&chunk);
        }
        assert_eq!(lt.current_line().len(), 512);
        // 10 MiB without a newline; the previous version took seconds.
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn allowlist_check() {
        let list = vec!["ssh".to_string(), "kubectl".to_string()];
        assert!(is_allowlisted("ssh", &list));
        assert!(!is_allowlisted("bash", &list));
    }

    #[test]
    fn recent_names_dedups_adjacent() {
        let mut r = RecentNames::new(3);
        r.push("bash".into());
        r.push("bash".into());
        r.push("ssh".into());
        assert_eq!(r.buf, vec!["bash".to_string(), "ssh".to_string()]);
    }
}
