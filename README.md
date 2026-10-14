# tacitty

A prompt-aware password alias injector for Linux terminals. Type a short
alias like `@prod-db` into any terminal password prompt — `sudo`, `ssh`,
`psql`, `mysql`, `gpg`, `read -s`, Python's `getpass`, and so on — and it's
transparently replaced with the real secret from a local encrypted vault,
before the program on the other end ever sees the alias text.

The alias is bound to the **secret**, not to a hostname or application: the
same `@prod-db` works at a `sudo` prompt, an `ssh` password prompt, or a
`psql` prompt.

The core property that makes this safe to leave running all the time:
**expansion only happens when the terminal is actually in secret-input
mode.** Type `@prod-db` in a normal shell line, in `vim`, in `less`, or in a
chat app, and nothing happens — it's passed through literally. There are no
global keyboard hooks, no clipboard involved, and no X11/Wayland keystroke
injection.

```
$ tacitty init                 # create the vault, enable auto-start
$ tacitty add prod-db          # store a secret under an alias
                               # (open a new terminal — it's already wrapped)
$ sudo systemctl restart nginx
[sudo] password for alice: @prod-db⏎     # nothing is echoed; the real
                                          # secret is sent to sudo instead
```

## How detection works

On Linux, `tcgetattr()` on a pty's **master** fd returns the **slave**'s
termios. When the first byte of a new input line arrives, tacitty checks:

```
secret_mode = !(c_lflag & ECHO) && ((c_lflag & ICANON) || (c_lflag & ECHONL))
```

Programs reading passwords — `sudo`, `passwd`, `read -s`, Python's
`getpass()`, `psql`, `mysql`, `pinentry-tty`, `ssh-add` — put the terminal
into canonical mode with echo off, so this matches. Editors, pagers, and TUI
programs also disable echo, but run in **raw** (non-canonical) mode, so they
don't match — this is what keeps `@alias` inert everywhere that isn't
actually a secret prompt. (This detection approach follows the same model
used by [Ghostty](https://ghostty.org)'s lock indicator and the
[ghostel](https://github.com/telesoho/ghostel) Emacs terminal.)

Inside an interactive `ssh`/`mosh`/`telnet`/`docker exec -it`/`kubectl exec
-it` session, the *local* pty is raw (the client itself sets that), so the
termios check can't see the remote host's prompt. As a fallback, tacitty
also watches the *output*: if the foreground process is one of that
allow-list (configurable), and the current output line matches a configured
prompt regex (default: `(password|passphrase|passcode|pin)...:\s*$`), it
treats that as a possible remote prompt. Because this fallback can, in
principle, misfire on a remote line that isn't really a secret prompt, it
defaults to asking for a one-key local confirmation before sending anything
(`remote.mode = "confirm"`; `"auto"` and `"off"` are also available).

## Install

One command installs a prebuilt static binary for x86_64 or ARM64 Linux. It
downloads the binary from GitHub Releases, verifies its SHA-256 checksum,
and installs it to `~/.local/bin`, with no root needed:

```sh
curl -fsSL https://raw.githubusercontent.com/Sriramm07/tacitty/main/install.sh | sh
```

Set `TACITTY_VERSION=v0.1.0` to install a specific release, or
`TACITTY_INSTALL_DIR=/some/dir` to install somewhere else.

Other options:

- **Debian / Ubuntu:** download the `.deb` for your architecture from the
  [latest release](https://github.com/Sriramm07/tacitty/releases/latest),
  then run `sudo apt install ./tacitty_*.deb`.
- **Manual:** download `tacitty-<version>-<arch>-unknown-linux-musl.tar.gz`
  from the release page, check it against its `.sha256` file, and put the
  `tacitty` binary anywhere on your `PATH`.
- **From source:** see [Building from source](#building-from-source).

## Setup

Once installed:

```sh
tacitty init
tacitty add prod-db
```

That's it: `init` also turns on **auto-start**, so every new interactive
terminal (new tabs, new windows, after a reboot, SSH logins to this
machine) starts inside `tacitty shell` with no further setup. Concretely,
it:

- copies the running binary to `~/.local/bin/tacitty` (skipped for
  packaged installs under `/usr` or `/opt`), so the hook keeps working even
  if the downloaded file is moved or deleted, and
- adds a marked `# >>> tacitty autostart >>>` block to `~/.bashrc` and/or
  `~/.zshrc` (every one that exists, plus your login shell's).

Your login shell is **not** changed. Scripts, `scp`, cron jobs and
`ssh host cmd` never see the wrapper, because the hook only runs for
interactive shells on a terminal. If the wrapper fails to start, for
example because of a bad config file, the hook prints a warning and you get
your plain shell, so a broken install can't lock you out of your terminal.

To switch back:

- `tacitty disable` removes the block (`tacitty enable` puts it back).
- `NO_TACITTY=1 bash` skips the wrapper for one shell. To skip it for a
  whole login session, add `export NO_TACITTY=1` to `~/.profile`.
- `tacitty init --no-autostart` creates the vault without enabling
  auto-start.

Auto-start covers bash and zsh. For other shells, run `tacitty shell`
manually or set your terminal emulator's command to `tacitty shell`.

**For tmux**, wrap each *pane*, not the tmux client itself — see
[`contrib/tacitty.tmux.conf`](contrib/tacitty.tmux.conf) and the "Known
limitations" note below on why.

## CLI reference

```
tacitty init [--no-autostart]     create the native vault, set the master passphrase,
                                  and enable auto-start
tacitty enable | disable          turn auto-start in new terminals on / off
tacitty add <alias>               read a secret from /dev/tty (echo off, confirmed twice)
tacitty add <alias> --generate [--length N]
tacitty rm <alias>
tacitty mv <old> <new>
tacitty ls                        aliases + timestamps only, never secrets
tacitty get <alias>               print to stdout; refuses a tty unless --force
tacitty shell [-- <cmd> ...]      run $SHELL (or <cmd>) inside the pty wrapper
tacitty lock | unlock | status
tacitty doctor                    check termios detection, agent, backends, pinentry, nesting, auto-start
tacitty config                    print the config file path
```

Alias names must match `^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$`.

## Configuration

`~/.config/tacitty/config.toml` (all fields optional; shown here at their
defaults):

```toml
trigger = "@"
backend = "native"          # native | pass | secret-service | command
on_miss = "bell"            # bell | literal
idle_lock_minutes = 15
title_indicator = true

[remote]
mode = "confirm"            # confirm | auto | off
processes = ["ssh", "mosh-client", "telnet", "docker", "kubectl", "podman"]
prompt_regex = '(?i)(password|passphrase|passcode|pin)[^\n]*:\s*$'

[pass]
prefix = "tacitty"

[command]
get = "bw get password {alias}"
```

### Backends

- **`native`** (default) — `~/.local/share/tacitty/vault.age`, a single
  [`age`](https://github.com/str4d/rage)-encrypted file (scrypt passphrase
  recipient), permissions `0600`. Reads go through a per-user background
  agent (`tacitty agent`, auto-started on first use) so the passphrase is
  only needed once per idle-timeout window rather than on every alias.
- **`pass`** — reads from [`pass`](https://www.passwordstore.org/) under
  `<prefix>/<alias>`. Read-only from tacitty's side; manage entries with
  `pass` itself.
- **`secret-service`** — reads via `secret-tool lookup application tacitty
  alias <alias>` (part of `libsecret`'s own CLI tools — chosen over a D-Bus
  client library specifically to avoid pulling in a large async dependency
  tree for this one optional backend). `tacitty add` can write to this
  backend too.
- **`command`** — runs a configured command template (`{alias}` is
  substituted) and reads the secret from its first line of stdout. The
  template is split into argv words by hand (simple whitespace/quote
  handling) and executed directly — never through a shell — so there's no
  injection risk from alias content reaching a shell's parsing.

## Security

**Threat model — in scope:** shoulder surfing; shell history; clipboard
sniffers and clipboard managers; X11 keyloggers observing injected
keystrokes (there are none — nothing is ever injected outside the pty pair
tacitty itself owns); accidental expansion into the wrong application;
secrets in logs, core dumps, swap, or terminal scrollback.

**Out of scope:** a root compromise; a malicious process running as the
*same* user with `ptrace` or `/proc/<pid>/mem` access to `tacitty shell` or
`tacitty agent` (mitigated where cheap — see below — but not eliminated);
an attacker who can overwrite the vault file or config directly.

What tacitty does about it:

- Secrets never touch argv, environment variables, the clipboard, disk
  (except the encrypted vault), log output, or the wrapped child's own
  output stream.
- The wrapper and agent processes disable core dumps and ptrace-ability at
  startup (`PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`).
- Every buffer that can hold a secret is a `SecretBuf` (wraps `zeroize`,
  best-effort `mlock`s its allocation) or a `secrecy::SecretString`;
  contents are wiped the moment they're no longer needed, and `Debug` never
  prints them.
- `TACITTY_LOG` logs fixed state-transition labels only (`"agent:
  unlocked"`, `"agent: alias resolved"`) — never input bytes, buffer
  contents, alias values, or secrets. This is enforced structurally: the
  logging function's only parameter type is `&'static str`.
- Secrets are only ever written to the pty master while secret mode (or a
  confirmed remote-fallback mode) is active.
- The real terminal's termios is restored via an RAII guard on every exit
  path — normal exit, an early return, a panic unwind, or the
  signal-triggered break out of the main loop.
- Vault file: `0600`; its directory: `0700`; the loader refuses to touch a
  vault that's group- or world-readable, or not owned by the running user.
- The agent's Unix socket verifies each connecting peer's UID via
  `SO_PEERCRED` and rejects anyone else — but note this means any other
  process running as the *same* user can query it while the vault is
  unlocked (the same trust boundary `ssh-agent` operates under).
- `cargo audit` and `cargo deny` run in CI on every push (see
  `.github/workflows/ci.yml`); `deny.toml` additionally bans `openssl`/
  `openssl-sys` from ever entering the dependency tree, since the
  cryptography here (`age`, `chacha20poly1305`, `scrypt`) is all pure Rust.

## Known limitations

- **`pinentry-curses` and `pinentry-gnome3`** (gpg's default pinentry
  programs) run in raw mode or as a separate GUI, so tacitty can't see
  their prompts. If you want alias expansion at gpg prompts, switch
  `gpg-agent`'s `pinentry-program` to `pinentry-tty`.
- **Nested wrappers**: if `tacitty shell` wraps a `tmux` (or `screen`)
  *client*, detection only ever sees that client's own raw pty — never the
  termios of whatever's running inside an individual pane. Run `tacitty
  shell` as the command **inside** each pane instead (see
  `contrib/tacitty.tmux.conf`).
- Any program that reads a password in raw mode with its own custom
  masking (rather than the kernel's canonical-mode echo suppression) won't
  be detected.
- The remote-ssh fallback is heuristic (a foreground-process allow-list
  plus a regex over the current output line) and can, in principle,
  misfire on an unusual remote prompt — hence it defaults to asking for a
  local confirmation before sending anything.
- The local termios check has an inherent small race: a program can print
  its prompt text a moment before or after it actually disables terminal
  echo, and an extremely fast keystroke (or scripted/pasted input) right at
  that instant could theoretically land in the gap. tacitty retries the
  check briefly, but only in the moment right after fresh output arrives
  (so ordinary typing pays no extra latency) — this narrows the window but
  cannot close it with absolute certainty for a sufficiently pathological
  timing.
- Root compromise, or another process running as the same user with
  `ptrace`/`/proc/<pid>/mem` access, is out of scope (see the threat model
  above) — mitigated (disabled core dumps, disabled ptrace-ability) but not
  eliminated, since a sufficiently privileged attacker can always attach a
  debugger to a running process regardless of what that process asks the
  kernel for.

## Building from source

Requires Rust 1.80+.

```sh
cargo build --release
sudo install -m 755 target/release/tacitty /usr/local/bin/tacitty
```

Static musl binaries for `x86_64` and `aarch64` (no glibc dependency) are
built by CI on every push — see the Actions tab for `tacitty-<target>`
artifacts — or build one locally:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Testing

```sh
cargo test --lib                                    # 49 unit tests, no I/O —
                                                      # includes 300,000-sample
                                                      # randomized robustness
                                                      # checks (stable-Rust
                                                      # complement to the
                                                      # nightly-only fuzz
                                                      # targets; see
                                                      # fuzz/README.md)
cargo test --test integration -- --test-threads=1    # drives the real
                                                      # binary through real
                                                      # ptys (bash, python,
                                                      # a fake ssh, ...)
```

The integration suite is single-threaded on purpose: each test starts its
own background agent daemon in an isolated `HOME`/`XDG_RUNTIME_DIR`, and on
a heavily loaded or low-core-count machine, running many of those
concurrently introduces enough scheduling jitter to make the termios-race
mitigation above meaningfully more likely to matter than it would in normal
use. See `fuzz/README.md` for the state-machine, alt-screen-tracker, and
vault-decoder fuzz targets.

## Packaging

- **Releases:** pushing a tag like `v0.1.0` (it must match the version in
  `Cargo.toml`) runs `.github/workflows/release.yml`. It publishes a GitHub
  Release with static musl tarballs and `.deb` packages for x86_64 and
  aarch64, each with a `.sha256` file. `install.sh` installs from these.
- `cargo install --path .` — installs from source into `~/.cargo/bin`.
- `.deb` metadata is in `Cargo.toml`'s `[package.metadata.deb]`; build with
  [`cargo-deb`](https://github.com/kornelski/cargo-deb):
  `cargo deb` (produces `target/debian/tacitty_<version>-1_amd64.deb`).
- `packaging/PKGBUILD` — Arch Linux / AUR package definition.

## Non-goals (v1)

GUI applications and browser forms; Windows and macOS (the termios/pty
model is POSIX, so macOS support is a plausible future addition, just not
attempted here); cloud sync; team/shared-vault support; TOTP; replacing a
full password manager.

## License

Copyright (c) 2026 Sriram P.

tacitty is source-available under the
[PolyForm Noncommercial License 1.0.0](LICENSE). You may use, modify and
share it for any **noncommercial** purpose: personal use, hobby projects,
study and research, and use by charities, educational institutions and
government bodies. **Commercial use is not permitted**, including selling
it, bundling it into a paid product or service, or using it inside a
for-profit business.

For a commercial license, contact Sriram P at sriram_297@yahoo.com.
