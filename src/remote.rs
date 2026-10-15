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
    /// Characters, not bytes: trimming a `String` by byte count can split a
    /// multi-byte character and panic.
    chars: VecDeque<char>,
    line: String,
    max_chars: usize,
}

impl LinePerform {
    fn clear(&mut self) {
        self.chars.clear();
        self.line.clear();
    }
}

impl Perform for LinePerform {
    fn print(&mut self, c: char) {
        self.chars.push_back(c);
        if self.chars.len() > self.max_chars {
            self.chars.pop_front();
            self.line = self.chars.iter().collect();
        } else {
            self.line.push(c);
        }
    }

    fn execute(&mut self, byte: u8) {
        // Newline, carriage return or backspace: the tracked text no longer
        // matches what's on screen at the cursor, so start over.
        if matches!(byte, b'\n' | b'\r' | 0x08) {
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
        // Anything that moves the cursor or erases text means the line on
        // screen is no longer simply "what was printed since the last
        // newline". Forget it rather than guess: a missed remote prompt is
        // safe, a false one is not.
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
                | 'P'
                | 'X'
                | '@'
                | 'd'
                | 'f'
                | 'u'
        ) {
            self.clear();
        }
    }
}

impl LineTracker {
    pub fn new() -> Self {
        LineTracker {
            parser: Parser::new(),
            perform: LinePerform {
                chars: VecDeque::new(),
                line: String::new(),
                max_chars: 512,
            },
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.parser.advance(&mut self.perform, bytes);
    }

    /// The plain text of the output since the last newline.
    pub fn current_line(&self) -> &str {
        &self.perform.line
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
pub fn proc_comm(pid: i32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
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
