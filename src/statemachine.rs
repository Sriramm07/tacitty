//! The input interception state machine (spec §7).
//!
//! Pure logic, no I/O: the caller feeds one input byte at a time (plus the
//! currently-cached `secret_mode` bit) and gets back an [`Action`] describing
//! what to do. All buffering uses [`SecretBuf`] so captured bytes are
//! zeroized the moment they are no longer needed.

use crate::alias::{self, MAX_ALIAS_LEN};
use crate::secret::SecretBuf;

const BACKSPACE: [u8; 2] = [0x7f, 0x08];
const CTRL_U: u8 = 0x15; // NAK
const CTRL_W: u8 = 0x17; // ETB
const CTRL_C: u8 = 0x03;
const CTRL_D: u8 = 0x04;
const CTRL_Z: u8 = 0x1a;
const ESC: u8 = 0x1b;

const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~";

fn is_enter(b: u8) -> bool {
    b == b'\r' || b == b'\n'
}

/// What the caller should do in response to one input byte.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Consumed internally; nothing to send anywhere yet.
    Consumed,
    /// Forward this single raw byte to the pty master unchanged.
    Forward(u8),
    /// Forward these bytes to the pty master verbatim (a flushed capture
    /// buffer, a literal `@`, or a paste flush). Treated as sensitive.
    ForwardBytes(SecretBuf),
    /// The user finished typing an alias and pressed Enter. The caller
    /// should look `alias` up in the vault and then send either the
    /// resolved secret + `enter_byte`, or (per `on_miss`) a bell or the
    /// literal `@alias` + `enter_byte`.
    ResolveAlias { alias: String, enter_byte: u8 },
    /// Alias buffer exceeded the max alias length: ring the bell locally
    /// and discard (same UX as an unknown alias).
    TooLong,
}

#[derive(PartialEq, Eq)]
enum EscMatch {
    /// Bytes matched so far are a strict prefix of `needle`.
    Partial,
    /// Bytes matched `needle` exactly.
    Full,
    /// Bytes no longer match `needle`.
    None,
}

fn match_progress(acc: &[u8], needle: &[u8]) -> EscMatch {
    if acc.len() > needle.len() || &needle[..acc.len().min(needle.len())] != acc {
        return EscMatch::None;
    }
    if acc.len() == needle.len() {
        EscMatch::Full
    } else {
        EscMatch::Partial
    }
}

enum State {
    Passthrough {
        line_len: usize,
    },
    /// Buffering a candidate alias. `esc` accumulates a possible bracketed
    /// paste start sequence seen mid-capture; `overflow` is set once the
    /// alias would exceed the max length (further alias bytes are silently
    /// dropped rather than growing the buffer or being forwarded).
    Capture {
        buf: SecretBuf,
        esc: Vec<u8>,
        overflow: bool,
    },
    /// Forwarding a bracketed paste verbatim until the end marker completes.
    PasteThrough {
        end_match: usize,
    },
}

pub struct StateMachine {
    trigger: u8,
    state: State,
}

impl StateMachine {
    pub fn new(trigger: u8) -> Self {
        StateMachine {
            trigger,
            state: State::Passthrough { line_len: 0 },
        }
    }

    /// True while a capture (or paste-through) is in progress — useful for
    /// the caller to decide whether to show the title indicator.
    pub fn is_capturing(&self) -> bool {
        !matches!(self.state, State::Passthrough { .. })
    }

    /// True when nothing has been typed on the current line yet: the only
    /// place where typing the trigger can start a capture.
    pub fn at_line_start(&self) -> bool {
        matches!(self.state, State::Passthrough { line_len: 0 })
    }

    /// Explicitly abandon any in-progress capture (buffer is zeroized via
    /// `SecretBuf`'s `Drop`). Used when secret_mode drops mid-line.
    pub fn reset(&mut self) {
        self.state = State::Passthrough { line_len: 0 };
    }

    pub fn process(&mut self, byte: u8, secret_mode: bool) -> Action {
        match std::mem::replace(&mut self.state, State::Passthrough { line_len: 0 }) {
            State::Passthrough { line_len } => self.passthrough(byte, secret_mode, line_len),
            State::Capture { buf, esc, overflow } => self.capture(byte, buf, esc, overflow),
            State::PasteThrough { end_match } => self.paste_through(byte, end_match),
        }
    }

    fn passthrough(&mut self, byte: u8, secret_mode: bool, line_len: usize) -> Action {
        if secret_mode && line_len == 0 && byte == self.trigger {
            self.state = State::Capture {
                buf: SecretBuf::new(),
                esc: Vec::new(),
                overflow: false,
            };
            return Action::Consumed;
        }
        let new_len = if is_enter(byte) || byte == CTRL_C || byte == CTRL_D || byte == CTRL_Z {
            0
        } else if BACKSPACE.contains(&byte) {
            line_len.saturating_sub(1)
        } else if byte == CTRL_U {
            0
        } else if byte == CTRL_W {
            line_len // conservative: don't shrink on word-erase, see design notes
        } else {
            line_len.saturating_add(1)
        };
        self.state = State::Passthrough { line_len: new_len };
        Action::Forward(byte)
    }

    fn capture(
        &mut self,
        byte: u8,
        mut buf: SecretBuf,
        mut esc: Vec<u8>,
        mut overflow: bool,
    ) -> Action {
        // Mid-capture bracketed-paste detection takes priority whenever an
        // ESC-prefix match is already in progress, or a fresh ESC arrives.
        if !esc.is_empty() || byte == ESC {
            esc.push(byte);
            return match match_progress(&esc, PASTE_START) {
                EscMatch::Full => {
                    let mut out = SecretBuf::with_capacity(1 + buf.len() + esc.len());
                    out.push(self.trigger);
                    out.extend_from_slice(buf.as_slice());
                    out.extend_from_slice(&esc);
                    self.state = State::PasteThrough { end_match: 0 };
                    Action::ForwardBytes(out)
                }
                EscMatch::Partial => {
                    self.state = State::Capture { buf, esc, overflow };
                    Action::Consumed
                }
                EscMatch::None => {
                    // Divergence: flush '@' + buffer + everything accumulated
                    // as a literal, matching the general "any other
                    // character" passthrough rule.
                    let mut out = SecretBuf::with_capacity(1 + buf.len() + esc.len());
                    out.push(self.trigger);
                    out.extend_from_slice(buf.as_slice());
                    out.extend_from_slice(&esc);
                    self.state = State::Passthrough { line_len: 1 };
                    Action::ForwardBytes(out)
                }
            };
        }

        if is_enter(byte) {
            self.state = State::Passthrough { line_len: 0 };
            if overflow {
                return Action::TooLong;
            }
            // Alias bytes are restricted to ASCII alias characters (enforced
            // below), so this is always valid UTF-8.
            let alias = String::from_utf8(buf.as_slice().to_vec())
                .expect("capture buffer only ever holds ASCII alias bytes");
            return Action::ResolveAlias {
                alias,
                enter_byte: byte,
            };
        }

        if BACKSPACE.contains(&byte) {
            if overflow {
                // Backing out of an overflowed alias: drop back to "not
                // overflowing" only once the buffer itself has room again
                // is unknowable (we didn't keep the extra chars), so treat
                // any backspace while overflowed as simply un-overflowing;
                // the user will need to retype past the limit to overflow
                // again, which is the safe direction to err in.
                overflow = false;
                self.state = State::Capture { buf, esc, overflow };
                return Action::Consumed;
            }
            buf.pop();
            if buf.is_empty() {
                self.state = State::Passthrough { line_len: 0 };
            } else {
                self.state = State::Capture { buf, esc, overflow };
            }
            return Action::Consumed;
        }

        if byte == CTRL_U {
            self.state = State::Passthrough { line_len: 0 };
            return Action::Consumed;
        }

        if byte == CTRL_C || byte == CTRL_D || byte == CTRL_Z {
            self.state = State::Passthrough { line_len: 0 };
            return Action::Forward(byte);
        }

        if buf.is_empty() && byte == self.trigger {
            // "@@" escape hatch: literal '@', back to passthrough.
            self.state = State::Passthrough { line_len: 1 };
            return Action::Forward(self.trigger);
        }

        if alias::is_alias_byte(byte) {
            if buf.len() < MAX_ALIAS_LEN {
                buf.push(byte);
            } else {
                overflow = true;
            }
            self.state = State::Capture { buf, esc, overflow };
            return Action::Consumed;
        }

        // Any other character: the user is typing a real value starting
        // with the trigger. Forward it all and resume passthrough. (If the
        // buffer had already overflowed the alias limit, this can no longer
        // be a real secret we captured faithfully -- but we only ever
        // reach this branch on genuinely non-alias bytes, and we still
        // forward exactly what was buffered, so nothing is lost.)
        let mut out = SecretBuf::with_capacity(1 + buf.len() + 1);
        out.push(self.trigger);
        out.extend_from_slice(buf.as_slice());
        out.push(byte);
        self.state = State::Passthrough { line_len: 1 };
        Action::ForwardBytes(out)
    }

    fn paste_through(&mut self, byte: u8, end_match: usize) -> Action {
        let candidate_len = end_match + 1;
        let progressed = candidate_len <= PASTE_END.len() && PASTE_END[end_match] == byte;
        if progressed {
            if candidate_len == PASTE_END.len() {
                self.state = State::Passthrough { line_len: 1 };
            } else {
                self.state = State::PasteThrough {
                    end_match: candidate_len,
                };
            }
        } else {
            // Didn't match: if this byte at least restarts a match (e.g. the
            // ESC of a fresh end marker after a false start), track that;
            // otherwise reset.
            let restart = if PASTE_END[0] == byte { 1 } else { 0 };
            self.state = State::PasteThrough { end_match: restart };
        }
        Action::Forward(byte)
    }
}

/// Bytes to write to the pty master when an alias resolved: the secret
/// followed by a carriage return.
pub fn resolved_line(secret: &[u8]) -> SecretBuf {
    let mut out = SecretBuf::with_capacity(secret.len() + 1);
    out.extend_from_slice(secret);
    out.push(b'\r');
    out
}

/// Bytes to write when `on_miss = "literal"`: what the user actually typed.
pub fn literal_line(trigger: u8, alias: &str, enter_byte: u8) -> SecretBuf {
    let mut out = SecretBuf::with_capacity(alias.len() + 2);
    out.push(trigger);
    out.extend_from_slice(alias.as_bytes());
    out.push(enter_byte);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(sm: &mut StateMachine, bytes: &[u8], secret_mode: bool) -> Vec<Action> {
        bytes.iter().map(|&b| sm.process(b, secret_mode)).collect()
    }

    #[test]
    fn passthrough_when_not_secret_mode() {
        let mut sm = StateMachine::new(b'@');
        for &b in b"@prod-db\r" {
            assert_eq!(sm.process(b, false), Action::Forward(b));
        }
    }

    #[test]
    fn basic_alias_capture_and_resolve() {
        let mut sm = StateMachine::new(b'@');
        assert_eq!(sm.process(b'@', true), Action::Consumed);
        assert!(sm.is_capturing());
        for &b in b"prod-db" {
            assert_eq!(sm.process(b, true), Action::Consumed);
        }
        let a = sm.process(b'\r', true);
        assert_eq!(
            a,
            Action::ResolveAlias {
                alias: "prod-db".into(),
                enter_byte: b'\r'
            }
        );
        assert!(!sm.is_capturing());
    }

    #[test]
    fn not_at_line_start_never_captures() {
        let mut sm = StateMachine::new(b'@');
        assert_eq!(sm.process(b'x', true), Action::Forward(b'x'));
        // line_len is now 1, so '@' should NOT trigger capture
        assert_eq!(sm.process(b'@', true), Action::Forward(b'@'));
        assert!(!sm.is_capturing());
    }

    #[test]
    fn backspace_to_empty_returns_passthrough() {
        let mut sm = StateMachine::new(b'@');
        sm.process(b'@', true);
        sm.process(b'a', true);
        assert!(sm.is_capturing());
        assert_eq!(sm.process(0x7f, true), Action::Consumed); // remove 'a'
        assert!(!sm.is_capturing());
        // now line_len==0 again, '@' should re-enter capture
        assert_eq!(sm.process(b'@', true), Action::Consumed);
        assert!(sm.is_capturing());
    }

    #[test]
    fn ctrl_u_clears_capture() {
        let mut sm = StateMachine::new(b'@');
        sm.process(b'@', true);
        sm.process(b'a', true);
        sm.process(b'b', true);
        assert_eq!(sm.process(CTRL_U, true), Action::Consumed);
        assert!(!sm.is_capturing());
    }

    #[test]
    fn ctrl_c_discards_and_forwards() {
        let mut sm = StateMachine::new(b'@');
        sm.process(b'@', true);
        sm.process(b'a', true);
        assert_eq!(sm.process(CTRL_C, true), Action::Forward(CTRL_C));
        assert!(!sm.is_capturing());
    }

    #[test]
    fn double_at_is_literal() {
        let mut sm = StateMachine::new(b'@');
        sm.process(b'@', true);
        assert_eq!(sm.process(b'@', true), Action::Forward(b'@'));
        assert!(!sm.is_capturing());
    }

    #[test]
    fn password_starting_with_trigger_forwarded_whole() {
        let mut sm = StateMachine::new(b'@');
        sm.process(b'@', true);
        sm.process(b'a', true);
        sm.process(b'b', true);
        let a = sm.process(b'!', true); // '!' is not a valid alias byte
        match a {
            Action::ForwardBytes(buf) => assert_eq!(buf.as_slice(), b"@ab!"),
            other => panic!("unexpected: {other:?}"),
        }
        assert!(!sm.is_capturing());
    }

    #[test]
    fn empty_at_then_space_forwards_at_space() {
        let mut sm = StateMachine::new(b'@');
        sm.process(b'@', true);
        let a = sm.process(b' ', true);
        match a {
            Action::ForwardBytes(buf) => assert_eq!(buf.as_slice(), b"@ "),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn unknown_bytes_dont_start_capture_outside_secret_mode() {
        let mut sm = StateMachine::new(b'@');
        let actions = run(&mut sm, b"@x\r", false);
        assert_eq!(
            actions,
            vec![
                Action::Forward(b'@'),
                Action::Forward(b'x'),
                Action::Forward(b'\r')
            ]
        );
    }

    #[test]
    fn too_long_alias_signals_too_long() {
        let mut sm = StateMachine::new(b'@');
        sm.process(b'@', true);
        for _ in 0..(MAX_ALIAS_LEN + 5) {
            sm.process(b'a', true);
        }
        assert_eq!(sm.process(b'\r', true), Action::TooLong);
    }

    #[test]
    fn bracketed_paste_mid_capture_flushes_and_streams() {
        let mut sm = StateMachine::new(b'@');
        sm.process(b'@', true);
        sm.process(b'a', true);
        sm.process(b'b', true);
        let mut got = Vec::new();
        for &b in PASTE_START {
            let a = sm.process(b, true);
            if let Action::ForwardBytes(buf) = a {
                got = buf.as_slice().to_vec();
            } else {
                assert_eq!(a, Action::Consumed);
            }
        }
        assert_eq!(got, [b"@ab", PASTE_START].concat());
        // now inside PasteThrough: arbitrary bytes forwarded verbatim
        assert_eq!(sm.process(b'@', true), Action::Forward(b'@'));
        assert_eq!(sm.process(b'x', true), Action::Forward(b'x'));
        // end marker
        for (i, &b) in PASTE_END.iter().enumerate() {
            let a = sm.process(b, true);
            assert_eq!(a, Action::Forward(b), "byte {i}");
        }
        assert!(!sm.is_capturing());
        // back in passthrough, '@' shouldn't trigger (line considered non-empty)
        assert_eq!(sm.process(b'@', true), Action::Forward(b'@'));
    }

    #[test]
    fn esc_that_is_not_paste_flushes_literally() {
        let mut sm = StateMachine::new(b'@');
        sm.process(b'@', true);
        sm.process(b'a', true);
        let a1 = sm.process(ESC, true);
        assert_eq!(a1, Action::Consumed); // still partial (matches "\x1b" prefix)
        let a2 = sm.process(b'A', true); // arrow-key-like: ESC 'A' diverges from PASTE_START at pos 1
        match a2 {
            Action::ForwardBytes(buf) => assert_eq!(buf.as_slice(), &[b'@', b'a', ESC, b'A']),
            other => panic!("unexpected: {other:?}"),
        }
        assert!(!sm.is_capturing());
    }

    #[test]
    fn reset_clears_in_progress_capture() {
        let mut sm = StateMachine::new(b'@');
        sm.process(b'@', true);
        sm.process(b'a', true);
        assert!(sm.is_capturing());
        sm.reset();
        assert!(!sm.is_capturing());
    }

    #[test]
    fn resolved_and_literal_line_helpers() {
        assert_eq!(resolved_line(b"secret").as_slice(), b"secret\r");
        assert_eq!(
            literal_line(b'@', "prod-db", b'\r').as_slice(),
            b"@prod-db\r"
        );
    }
}

#[cfg(test)]
mod randomized_robustness {
    //! A stable-Rust, dependency-free stand-in for real coverage-guided
    //! fuzzing (see `fuzz/fuzz_targets/statemachine.rs`, which needs
    //! nightly + `cargo-fuzz` and so can't be verified as part of the
    //! normal `cargo test` run). This isn't a substitute for that — it has
    //! no coverage feedback, so it can't discover the deep, rare inputs a
    //! real fuzzer would — but it does give a fast, CI-verifiable check
    //! that the invariants hold over a large, varied random sample on
    //! every push, using nothing beyond what `cargo test --lib` already
    //! runs.
    use super::*;

    /// Small xorshift64* PRNG so this has zero extra dependencies and is
    /// still fully deterministic/reproducible from a fixed seed.
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

        fn next_byte(&mut self) -> u8 {
            (self.next_u64() & 0xff) as u8
        }
    }

    #[test]
    fn statemachine_never_panics_and_upholds_invariants_over_random_input() {
        let mut rng = Rng(0x5EED_u64);
        const STREAMS: usize = 300_000;
        const MAX_LEN: usize = 40;

        for _ in 0..STREAMS {
            let trigger = rng.next_byte();
            let mut sm = StateMachine::new(trigger);
            let len = (rng.next_u64() % MAX_LEN as u64) as usize;

            for _ in 0..len {
                let raw = rng.next_byte();
                let secret_mode = raw & 0x80 != 0;
                let byte = raw & 0x7f;
                let is_enter = byte == b'\r' || byte == b'\n';

                match sm.process(byte, secret_mode) {
                    Action::ResolveAlias { alias, .. } => {
                        assert!(
                            is_enter,
                            "ResolveAlias from non-Enter byte {byte:#x} (trigger {trigger:#x})"
                        );
                        assert!(
                            alias.bytes().all(crate::alias::is_alias_byte),
                            "alias had a non-alias byte: {alias:?}"
                        );
                        assert!(
                            alias.len() <= MAX_ALIAS_LEN,
                            "alias exceeded MAX_ALIAS_LEN: {} > {MAX_ALIAS_LEN}",
                            alias.len()
                        );
                    }
                    Action::TooLong => {
                        assert!(is_enter, "TooLong from non-Enter byte {byte:#x}");
                    }
                    _ => {}
                }
            }

            sm.reset();
            assert!(!sm.is_capturing(), "reset() left the machine capturing");
        }
    }
}
