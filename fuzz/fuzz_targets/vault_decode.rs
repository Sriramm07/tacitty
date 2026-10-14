//! Fuzzes the vault's plaintext decoder (spec §8.1's on-disk format). This
//! runs on attacker-adjacent input in the sense that it's whatever a
//! corrupted or truncated vault file decrypts to, so it must never panic
//! (out-of-bounds slice index, integer overflow on the length-prefixed
//! fields, etc.) regardless of what bytes it's handed.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    tacitty::vault::fuzz_decode(data);
});
