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
    line: String,
    max_len: usize,
}

impl Perform for LinePerform {
    fn print(&mut self, c: char) {
        self.line.push(c);
        if self.line.len() > self.max_len {
            let excess = self.line.len() - self.max_len;
            self.line.drain(..excess);
        }
    }

    fn execute(&mut self, byte: u8) {
        if byte == b'\n' || byte == b'\r' {
            self.line.clear();
        }
    }
    // CSI/OSC/ESC dispatches are intentionally no-ops: we only need the
    // printable text of the current line, and vte already keeps those
    // sequences out of `print`.
}

impl LineTracker {
    pub fn new() -> Self {
        LineTracker {
            parser: Parser::new(),
            perform: LinePerform {
                line: String::new(),
                max_len: 512,
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

// Silence "unused" for csi_dispatch etc. while keeping the doc comment
// self-explanatory; vte's default Perform impls are all no-ops already, so
// LinePerform doesn't need to implement them.
#[allow(unused)]
fn _assert_params_type_in_scope(_p: &Params) {}

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
        let re = Regex::new(r"(?i)(password|passphrase|passcode|pin)[^\n]*:\s*$").unwrap();
        for line in [
            "Password: ",
            "[sudo] password for sriram: ",
            "Enter passphrase for key '/home/sriram/.ssh/id_ed25519': ",
            "PIN: ",
        ] {
            assert!(looks_like_prompt(&re, line), "{line:?}");
        }
        for line in ["$ ", "Permission denied", "password changed successfully"] {
            assert!(!looks_like_prompt(&re, line), "{line:?}");
        }
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
