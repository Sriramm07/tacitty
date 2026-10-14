//! Fuzzes the input-interception state machine (spec §7, §11).
//!
//! The state machine is pure logic (no I/O), so it's a natural fuzz target:
//! feed it an arbitrary trigger byte, an arbitrary sequence of (byte,
//! secret_mode) pairs, and assert only the invariants that must always
//! hold, no matter what garbage arrives:
//!   - it never panics,
//!   - `ResolveAlias`/`TooLong` are only ever produced by an Enter byte,
//!   - the alias string handed back, when there is one, only ever
//!     contains bytes `alias::is_alias_byte` accepts,
//!   - `reset()` always returns it to a non-capturing state.
#![no_main]

use libfuzzer_sys::fuzz_target;
use tacitty::statemachine::{Action, StateMachine};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let trigger = data[0];
    let mut sm = StateMachine::new(trigger);

    for &raw in &data[1..] {
        // Use the top bit of each fuzz byte to choose secret_mode, so a
        // single byte stream drives both the trigger byte and the mode
        // flag without needing a structured input format.
        let secret_mode = raw & 0x80 != 0;
        let byte = raw & 0x7f;

        let is_enter = byte == b'\r' || byte == b'\n';
        match sm.process(byte, secret_mode) {
            Action::ResolveAlias { alias, .. } => {
                assert!(
                    is_enter,
                    "ResolveAlias produced by non-Enter byte {byte:#x}"
                );
                assert!(
                    alias.bytes().all(tacitty::alias::is_alias_byte),
                    "alias contained a non-alias byte: {alias:?}"
                );
            }
            Action::TooLong => {
                assert!(is_enter, "TooLong produced by non-Enter byte {byte:#x}");
            }
            _ => {}
        }
    }

    sm.reset();
    assert!(
        !sm.is_capturing(),
        "reset() left the state machine capturing"
    );
});
