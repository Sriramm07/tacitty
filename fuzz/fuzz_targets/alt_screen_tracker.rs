//! Fuzzes the alternate-screen output tracker (spec §6.1's "reject if the
//! output stream has switched to the alternate screen" rule). This only
//! ever needs to not panic and not grow its internal buffer unboundedly —
//! it has no other externally-visible invariants worth asserting, since
//! `is_active()`'s correctness on real escape sequences is covered by the
//! unit tests in `src/detect.rs`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use tacitty::detect::AltScreenTracker;

fuzz_target!(|chunks: Vec<Vec<u8>>| {
    let mut tracker = AltScreenTracker::new();
    for chunk in chunks.iter().take(64) {
        tracker.feed(&chunk[..chunk.len().min(256)]);
        let _ = tracker.is_active();
    }
});
