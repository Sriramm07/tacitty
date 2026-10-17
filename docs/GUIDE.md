# taciTTY guide

[← Back to the README](../README.md)

- [Install](#install)
- [How it works](#how-it-works)
- [Auto-start](#auto-start)
- [Groups](#groups)
- [Sharing aliases securely](#sharing)
- [Security](#security)
- [Development](#development)

<a id="install"></a>

## 📦 Install

The installer downloads the prebuilt binary for your architecture from
[GitHub Releases](https://github.com/Sriramm07/tacitty/releases/latest),
**verifies its SHA-256 checksum**, and installs it to `~/.local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/Sriramm07/tacitty/main/install.sh | sh
```

| Option | How |
|---|---|
| Specific version | `TACITTY_VERSION=v0.1.0` before `sh` |
| Different location | `TACITTY_INSTALL_DIR=/some/dir` before `sh` |
| By hand | Download `tacitty-<version>-<target>.tar.gz` from the release page (`<target>`: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin` or `aarch64-apple-darwin`), check it against its `.sha256`, and put `tacitty` on your `PATH` |
| From source | See [Building from source](#development) |

On Linux, taciTTY is a single static binary with no dependencies, so it
runs on any distribution.

**macOS** (Apple Silicon and Intel) uses the same installer and the same
commands. A few things differ:

- `~/.local/bin` isn't on your `PATH` by default on macOS. The installer
  tells you how to add it (for zsh: `export PATH="$HOME/.local/bin:$PATH"`
  in `~/.zshrc`). Auto-start works either way.
- The binaries aren't signed with an Apple Developer ID or notarized.
  That doesn't matter for `curl ... | sh` or `tacitty update`, which
  don't mark the file as downloaded. A `.tar.gz` downloaded **with a
  browser** is quarantined, and macOS refuses to run it; after checking
  its checksum, clear the flag with
  `xattr -d com.apple.quarantine tacitty`.
- The `secret-service` backend is Linux only.

**Updating:** run `tacitty update`, or `tacitty update --check` to only see
whether a newer version exists. It verifies the checksum and makes sure the
new binary runs before replacing the old one.

**Verifying a download (optional):** every release archive (`.tar.gz`)
comes with a build-provenance attestation, signed through GitHub, that
proves it was
built from this repository by its release workflow. With the
[GitHub CLI](https://cli.github.com):

```sh
gh attestation verify tacitty-v0.1.0-x86_64-unknown-linux-musl.tar.gz --repo Sriramm07/tacitty
```

<a id="how-it-works"></a>

## 🧭 How it works

```
 you type ──► tacitty (pty wrapper) ──► sudo / ssh / psql / ...
               │
               ├─ normal line?           pass every key through untouched
               └─ password prompt?       "@proddb⏎"  ──►  real secret + ⏎
                     ▲
                     └── is the terminal in "hidden input" mode right now?
```

taciTTY runs your shell inside a pseudo-terminal it controls. When you start
typing a line, it checks the terminal's mode. Programs that read passwords
switch the terminal to **canonical mode with echo off**. That's how the
password stays hidden while you type it. taciTTY only expands `@alias` in
exactly that mode:

```
secret_mode = !(c_lflag & ECHO) && ((c_lflag & ICANON) || (c_lflag & ECHONL))
```

Editors, pagers and other full-screen programs also turn echo off, but they
run in **raw** mode, so they never match. That's what keeps `@alias` inert
everywhere else.

<details>
<summary><b>Prompts on remote hosts (ssh, mosh, docker, kubectl)</b></summary>
<br>

Inside an interactive `ssh` (or `mosh`, `telnet`, `docker exec -it`,
`kubectl exec -it`) session, your *local* terminal is in raw mode, so the
check above can't see the remote host's prompt. As a fallback, taciTTY
watches the output. It treats `@alias` as a password only when **all** of
these hold:

- the program in the foreground is on an allow-list (`ssh`, `mosh-client`,
  `telnet`, `docker`, `kubectl`, `podman`);
- your local terminal is not showing what you type (so commands like
  `ssh host 'sudo -S ...'`, `ssh -T` or `kubectl exec -i` without `-t`, where
  it would be, never qualify);
- the current output line ends like a password prompt (default:
  `password`, `passphrase`, `passcode` or `pin` as a whole word, then `:`).

By default (`remote.mode = "auto"`) the secret is then sent straight away.
This is still a heuristic: if a remote program prints something that looks
like a password prompt but actually shows what you type, the secret would
be visible there. To be asked `send secret for @alias? [y/N]` first, set
`remote.mode = "confirm"`. To turn the fallback off, set `"off"`.

</details>

<a id="auto-start"></a>

## ⚙️ Auto-start

`tacitty init` makes every new interactive terminal start inside taciTTY:
new tabs and windows, after a reboot, and interactive SSH logins to this
machine. It:

- copies the binary to `~/.local/bin/tacitty` (skipped for installs under
  `/usr` or `/opt`, which includes Homebrew and MacPorts), so it keeps
  working if the downloaded file is moved;
- adds a marked `# >>> tacitty autostart >>>` block to `~/.bashrc` and/or
  `~/.zshrc`.

**On macOS**, zsh is the default shell and its `~/.zshrc` is hooked as
above. macOS terminals start *login* shells, and a bash login shell reads
`~/.bash_profile` instead of `~/.bashrc`, so for bash taciTTY also hooks
`~/.bash_profile` (or `~/.bash_login` / `~/.profile`, if that's the file
your bash reads). The shell inside taciTTY is started as a login shell
too, as the terminal would have, so it picks up the same settings.
`tacitty disable` removes the block from all of these files.

Your login shell is **not** changed. Scripts, `scp`, cron jobs and
`ssh host cmd` never go through taciTTY, because the hook only runs for
interactive terminals. If taciTTY fails to start, for example because of a
bad config file, you get your normal shell with a warning, so it can never
lock you out.

| To... | Run |
|---|---|
| Turn auto-start off / on | `tacitty disable` / `tacitty enable` |
| Skip it for one shell | `NO_TACITTY=1 bash` |
| Skip it for a whole login session | add `export NO_TACITTY=1` to `~/.profile` (zsh on macOS: `~/.zprofile`) |
| Create the vault without auto-start | `tacitty init --no-autostart` |

> [!NOTE]
> Auto-start supports **bash** and **zsh**. For other shells, run
> `tacitty shell` or set your terminal's command to `tacitty shell`.
> **For tmux**, wrap each *pane* rather than the tmux client: see
> [`contrib/tacitty.tmux.conf`](../contrib/tacitty.tmux.conf).

<a id="groups"></a>

## 🗂️ Groups

Groups let you organise aliases, for example keeping production passwords
together in a `prod` group, so you can list them together and share them
in one go. Every alias is in exactly one group. Alias names stay unique
across the whole vault, so you still just type `@proddb` at a prompt,
whichever group it's in. Groups never change how an alias is used.

Every vault starts with a group called `default`, which is also the
**default group**: the one new aliases go into when you don't name a group.
Aliases saved before groups existed are all in `default`.

```sh
tacitty add proddb --group prod             # save straight into a group
tacitty group move rootpw pgadmin --to prod # move existing aliases (the group is created if needed)
tacitty ls                                  # every alias, by group
tacitty ls -g prod                          # just one group
```

`tacitty ls` lists each group, marking the default, with its aliases and
their dates (never secrets):

```console
$ tacitty ls
default (default)
  @home                             created 2026-01-12 09:30:02 UTC  updated 2026-01-12 09:30:02 UTC

prod
  @pgadmin                          created 2026-02-03 14:11:47 UTC  updated 2026-02-03 14:11:47 UTC
  @proddb                           created 2026-01-12 09:31:15 UTC  updated 2026-03-01 08:02:40 UTC
```

| To... | Run |
|---|---|
| List groups and their sizes | `tacitty group ls` |
| Move aliases into a group | `tacitty group move <alias> ... --to <group>` |
| Rename a group | `tacitty group rename <old> <new>` |
| Delete a group | `tacitty group rm <group>` |
| See or change the default group | `tacitty group default [<group>]` |

- **Renaming** a group onto a name that's already in use is refused rather
  than merging the two; use `group move` to move aliases into an existing
  group. Renaming the default group keeps it the default.
- **Deleting** a group never deletes secrets: its aliases move into the
  default group. The default group itself can't be deleted; make another
  group the default first.
- A group exists while it holds aliases (or is the default group), so
  moving the last alias out of a group removes it.
- `tacitty add` on an alias that already exists keeps it in its group,
  unless you pass `--group`. `tacitty mv` keeps the renamed alias in its
  group.
- Group names: letters, digits, `.`, `_` and `-`, up to 64 characters,
  starting with a letter or digit.

Like the other commands that change the vault, the group commands ask for
your master passphrase and then lock the running agent, so it picks up the
change the next time it's unlocked.

<a id="sharing"></a>

## 🤝 Sharing aliases securely

`tacitty export` writes some or all of your aliases to an encrypted file,
and `tacitty import` adds them to someone else's vault. No server or
account is involved: you move the file however you like (`scp`, chat,
email, a USB stick), and only someone with the right key or passphrase can
open it.

**Choosing what to share.** Name aliases, groups (`-g` / `--group`,
repeatable), or both; with neither, every alias is exported. The file
records which group each alias is in.

**To specific people (public keys).** Encrypt to your colleagues' SSH
public keys (`ssh-ed25519`, or `ssh-rsa` of at least 2048 bits) or
[age](https://age-encryption.org) keys (`age1...`) with `--with-key`. Give
it once per person (or per key file). It produces **one file** that each
listed person can open with their own private key, and nobody else can:

```sh
# alice.pub can be her ~/.ssh/id_ed25519.pub, or a copy of https://github.com/alice.keys
tacitty export --group prod --with-key alice.pub --with-key bob.pub -o prod.tacitty

# A key can also be given directly (quote SSH keys, they contain spaces)
tacitty export proddb --with-key "ssh-ed25519 AAAAC3Nza... alice@laptop" --with-key age1qyqs... -o proddb.tacitty
```

A `--with-key` value that starts with `age1`, `ssh-ed25519 ` or `ssh-rsa `
is used as a key; anything else is read as a key file. A key file has one
key per line; blank lines and `#` comments are skipped, and any other line
that isn't a supported key stops the export with an error, so nobody is
left out by accident.

**With a passphrase.** Without `--with-key`, taciTTY asks for an export
passphrase (twice, at least 12 characters):

```sh
tacitty export -o team.tacitty --armor      # every alias, as pasteable text
```

`--armor` writes ASCII text (`-----BEGIN AGE ENCRYPTED FILE-----`) instead
of binary, for pasting into a chat or email. Either way, export asks for
your master passphrase first, writes the file with mode `0600`, and won't
overwrite an existing file unless you pass `--force`.

**Importing.** Your colleague runs:

```sh
tacitty import prod.tacitty                 # uses ~/.ssh/id_ed25519 or ~/.ssh/id_rsa
tacitty import prod.tacitty -i ~/.config/age/key.txt
tacitty import prod.tacitty --group shared  # put everything in one group
```

taciTTY works out from the file whether it needs a passphrase or a private
key. `-i` takes an age identity file or an SSH private key (it asks for the
key's passphrase if it has one) and can be repeated. Then it asks for the
importer's own master passphrase and adds the aliases to their vault, each
in the same group it was in for the sender (aliases the file doesn't put
in a group go into the importer's default group), and reports which group
got which aliases. `--group` puts them all into one group instead.
Aliases they already have are skipped and listed, unless they pass
`--overwrite` (a replaced alias moves to the imported alias's group).
Entries that can't be used (an invalid alias name, a password with control
characters) are skipped with a reason; secrets are never printed.

**What's in the file.** A standard [age](https://age-encryption.org/v1)
file whose content is a FIDO Alliance Credential Exchange Format (CXF)
v1.0 JSON document, with each alias as an item titled with the alias name
and holding its password, and each group as a CXF collection titled with
the group name. So the file can also be opened with
the standard tools, for example `age -d -i ~/.ssh/id_ed25519 prod.tacitty`
or `age -d team.tacitty` for a passphrase file. That prints the secrets in
plain text, so only do it when you mean to.

> [!IMPORTANT]
> - **It's a one-time copy.** Imported aliases don't stay in sync: later
>   changes on either side aren't shared.
> - **Sharing can't be undone.** Anyone who received a secret can keep
>   it. To revoke someone's access, change the real password (and send a
>   fresh export to the people who should still have it).
> - **Protect the passphrase.** For passphrase-protected files, the
>   passphrase is all that stands between the file and an offline guessing
>   attack. Use a long, random one and send it over a different channel
>   than the file (for example, the file by email and the passphrase by
>   phone).
> - Delete export files once they have been imported.
> - Secrets that aren't valid UTF-8 text can't be exported; export names
>   the alias and writes nothing.

<a id="security"></a>

## 🛡️ Security

**Protects against:** shoulder surfing; shell history; clipboard sniffers
and clipboard managers; keyloggers watching injected keystrokes (there are
none); expanding an alias into the wrong program; secrets ending up in
logs, core dumps or terminal scrollback. It also reduces, but can't rule
out, secrets being written to swap: memory locking is best effort, and
some buffers inside the encryption library aren't locked.

**Out of scope:** a compromised root account; malicious software running as
your own user that can attach a debugger to taciTTY (made harder, but not
prevented); someone who can overwrite the vault or config files.

<details>
<summary><b>What taciTTY does about it</b></summary>
<br>

- Secrets never touch command-line arguments, environment variables, the
  clipboard, disk (except the encrypted vault and encrypted export files
  you create), logs, or the output stream.
- Every taciTTY command turns off core dumps and debugger attachment at
  startup (`RLIMIT_CORE=0`, plus `PR_SET_DUMPABLE=0` on Linux and
  `PT_DENY_ATTACH` on macOS). Your own shell gets its normal core-dump
  limit back and stays debuggable. On macOS this means taciTTY can't be
  run under a debugger such as lldb: it exits at once.
- Every buffer that holds a secret is wiped as soon as it's no longer
  needed (`zeroize`), locked into memory where possible (`mlock`), and never
  printed in debug output. That includes the messages between taciTTY and
  its agent, and the agent doesn't keep your master passphrase after
  unlocking.
- `TACITTY_LOG` records fixed status labels only, never input, aliases or
  secrets. The logging function only accepts compile-time constant strings,
  so this is enforced by the compiler.
- Secrets are only written to the terminal while it's in password mode
  (or at a detected remote prompt), and that is **checked again at the
  moment of sending**. If the prompt went away while you were typing the
  alias (you pressed Ctrl-C, it timed out, or the program exited), nothing
  is sent and you see `the password prompt changed, so nothing was sent`.
- Secrets containing control characters (Tab, Enter, Ctrl-keys, Esc, DEL)
  are refused from every backend, since the terminal would act on them
  instead of passing them through.
- Your terminal's settings are restored when taciTTY exits, including on
  errors, internal crashes (panics) and termination signals. (No program can
  do this when killed with `SIGKILL`.)
- Vault file `0600`, directory `0700`. taciTTY refuses to open a vault that
  other users can read, or that you don't own.
- The agent's socket checks each caller's user ID and rejects everyone
  else. Like `ssh-agent`, other programs running as *you* can query it
  while the vault is unlocked.
- The dependency tree is checked with `cargo audit` and `cargo deny`. `openssl` is
  banned from the dependency tree; all cryptography is pure Rust (`age`,
  `chacha20poly1305`, `scrypt`).
- Releases are built by GitHub Actions with read-only permissions, every
  third-party action is pinned to an exact commit, and each release
  archive has a signed build-provenance attestation (see
  [Install](#install)).
- `tacitty update` and `install.sh` only download over HTTPS and verify each
  file's SHA-256 checksum before installing it.

</details>

<details>
<summary><b>Known limitations</b></summary>
<br>

- **gpg's default pinentry** (`pinentry-curses`, `pinentry-gnome3`) runs in
  raw mode or as a GUI, so taciTTY can't see it. Set gpg-agent's
  `pinentry-program` to `pinentry-tty` to use aliases at gpg prompts.
- **tmux / screen:** if taciTTY wraps the tmux *client*, it only sees
  tmux's own raw terminal. Run taciTTY inside each pane instead (see
  `contrib/tacitty.tmux.conf`).
- Programs that read passwords in raw mode with their own masking (rather
  than the terminal's built-in hidden input) aren't detected.
- The remote-prompt fallback is a heuristic and could, in principle, match
  a line that isn't really a password prompt. Use `remote.mode = "confirm"`
  if you want a confirmation first.
- The `.sha256` checksum comes from the same GitHub release as the binary,
  so it catches corrupted downloads but not a compromised release. To
  confirm a file was built by this repository's release workflow, verify
  its attestation with `gh attestation verify` (see [Install](#install)).
- A program can print its prompt a split second before it actually hides
  input. taciTTY briefly re-checks right after new output to narrow this
  window, but extremely fast or scripted input could still land in it.
- The "is the prompt still there?" check happens immediately before the
  secret is written. A prompt that ends in the tiny gap between that check
  and the write (well under a millisecond) can't be detected; no program
  outside the kernel can close that gap completely.
- **macOS support is new** and less tested than Linux. It's checked by a
  manually run CI workflow on GitHub's macOS runners (Apple Silicon and
  Intel), not yet by much day-to-day use. Please report anything odd.
- Windows isn't supported. GUI apps and browser forms are out of scope;
  taciTTY is not a full password manager.

</details>

<a id="development"></a>

## 🧑‍💻 Development

Requires Rust 1.80+.

```sh
cargo build --release                                  # build
cargo test --lib                                       # unit + randomized robustness tests
cargo test --features test-hooks --test integration -- --test-threads=1
                                                       # drive the real binary through real ptys
```

The integration tests need the `test-hooks` feature, which enables two
test-only switches (fast scrypt via `TACITTY_TEST_WORK_FACTOR`, and a local
release server via `TACITTY_RELEASES_URL`). Normal builds never include
them, so an environment variable can't weaken a real vault or redirect an
update. The integration tests run one at a time on purpose: each starts its own
background agent, and running many at once on a slow machine adds enough
timing jitter to make results flaky. See [`fuzz/README.md`](../fuzz/README.md)
for the fuzz targets.

<details>
<summary><b>Static builds, releases and the demo</b></summary>
<br>

- **Static binary:** `rustup target add x86_64-unknown-linux-musl`, then
  `cargo build --release --target x86_64-unknown-linux-musl`.
- **Releases:** pushing a tag like `v0.1.0` (it must match `Cargo.toml`)
  runs `.github/workflows/release.yml`, which publishes static Linux
  binaries and macOS binaries, each for x86_64 and aarch64, with `.sha256`
  checksums. `install.sh` and `tacitty update` install from these.
- **macOS:** `.github/workflows/macos.yml` (run it by hand from the Actions
  tab) builds and runs the whole test suite on Apple Silicon and Intel
  Macs. Without a Mac, `rustup target add aarch64-apple-darwin` and
  `cargo clippy --all-targets --features test-hooks --target
  aarch64-apple-darwin` still type-checks the macOS code.
- **Arch Linux:** `packaging/PKGBUILD`.
- **Demo GIF:** recorded with [VHS](https://github.com/charmbracelet/vhs)
  from [`assets/demo/demo.tape`](../assets/demo/demo.tape), against a
  throwaway Debian 13 server running sshd and PostgreSQL
  ([`assets/demo/server`](../assets/demo/server/Dockerfile)). Re-record with
  `sh assets/demo/record.sh` (needs Docker).

</details>
