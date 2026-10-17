# Fuzzing

Three targets, exercising the code that parses untrusted or attacker-adjacent
input:

- `statemachine` — the input-interception state machine (`src/statemachine.rs`).
  Pure logic, no I/O, so this is the highest-value target: it processes every
  keystroke typed at a terminal. Checks that resolving an alias or reporting
  "too long" only ever happens on an Enter byte, and that a resolved alias
  string only ever contains valid alias characters.
- `alt_screen_tracker` — the alternate-screen output scanner
  (`src/detect.rs`). Checks it never panics and never grows its internal
  buffer without bound, regardless of what a child process prints.
- `vault_decode` — the vault's plaintext decoder (`src/vault.rs`). This runs
  on whatever bytes a vault file decrypts to, so it must never panic on
  truncated, corrupt, or adversarial input — including a vault file an
  attacker got to write directly (see the threat model in the top-level
  README: an on-disk vault an attacker can overwrite bypasses the passphrase
  entirely, but it still must not crash the process it eventually gets
  parsed by). The corpus has samples of both layouts the decoder reads:
  the current one with groups (`PWV2`) and the original one (`PWV1`).

## These need nightly + cargo-fuzz, which stable `cargo test` can't verify

The three targets above type-check on stable (`cd fuzz && cargo check`
passes), but actually *running* them needs a nightly toolchain and
`cargo-fuzz`'s libFuzzer/sanitizer instrumentation — there's no way to
confirm from a plain `cargo test` run that they've ever found anything.
Run a short timed pass of all three (see below) after changing any of the
fuzzed modules, rather than taking them on faith.

As a stable-Rust complement — not a replacement, since it has no coverage
feedback and so can't discover the deep, rare inputs a real fuzzer would —
each of the three modules above also has a `#[test]` (in `src/statemachine.rs`,
`src/vault.rs`, `src/detect.rs` respectively) that runs the same invariant
checks over 300,000 random samples from a seeded PRNG, entirely on stable.
Those run as part of the normal `cargo test --lib` and take well under a
second combined — they're what's actually been verified in the environment
this project was built in.

## Running the real fuzz targets

Requires nightly Rust and `cargo-fuzz` (not run as part of the normal build):

```sh
cargo install cargo-fuzz
rustup toolchain install nightly
cargo +nightly fuzz run statemachine
cargo +nightly fuzz run alt_screen_tracker
cargo +nightly fuzz run vault_decode
```

Add `-- -max_total_time=300` (or similar) to bound a run. `cargo +nightly fuzz
run <target> -- -runs=100000` is a reasonable quick regression check to run
locally after touching the relevant module.

Crashes are saved under `fuzz/artifacts/<target>/`; reproduce one with:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>
```
