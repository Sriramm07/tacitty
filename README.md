<div align="center">

# 🔐 taciTTY

**Password aliases for your terminal.**<br>
Type `@proddb` at any password prompt and the real secret is sent instead.

[![CI](https://github.com/Sriramm07/tacitty/actions/workflows/ci.yml/badge.svg)](https://github.com/Sriramm07/tacitty/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Sriramm07/tacitty?color=8b5cf6)](https://github.com/Sriramm07/tacitty/releases/latest)
[![Platform](https://img.shields.io/badge/platform-Linux-0ea5e9)](docs/GUIDE.md#install)
[![Rust](https://img.shields.io/badge/built%20with-Rust-f97316)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-64748b)](#license)

<img src="assets/demo.gif" alt="tacitty demo: ssh to a server with @admin (unlocking the vault on first use), become root with @root, then open PostgreSQL with @pgdb" width="860">

</div>

---

## ✨ Why taciTTY?

Long, random passwords are safe but painful to type. Copy-pasting them leaks
them into clipboard managers, and typing them invites typos and shoulder
surfers. taciTTY lets you type a short, memorable alias instead. It works at
**any** terminal password prompt: `sudo`, `su`, `ssh`, `psql`, `mysql`,
`gpg`, `read -s`, Python's `getpass` and more.

- 🎯 **Only at real password prompts.** Type `@proddb` in a normal shell
  line, in `vim` or in `less`, and it stays plain text.
- 🔒 **Local and encrypted.** Secrets live in an
  [`age`](https://github.com/str4d/rage)-encrypted vault on your machine.
  Unlock it once and it locks itself again after 15 minutes of inactivity.
- 🙈 **Nothing to snoop on.** No clipboard, no keystroke injection, no
  global keyboard hooks, and nothing in your shell history or scrollback.
- 🌐 **Works over SSH too.** Prompts from remote hosts inside `ssh`,
  `mosh`, `docker exec` or `kubectl exec` sessions are recognised as well.
- ⚡ **Quick to set up.** One static binary. `tacitty init` turns it on for
  every new terminal automatically.

## 🚀 Quick start

```sh
# 1. Install (x86_64 or ARM64 Linux, no root needed)
curl -fsSL https://raw.githubusercontent.com/Sriramm07/tacitty/main/install.sh | sh

# 2. Create your vault and turn on auto-start
tacitty init

# 3. Save a secret under an alias
tacitty add proddb
```

Open a new terminal, and use it at any password prompt:

```console
$ sudo systemctl restart nginx
[sudo] password for sriram: @proddb⏎     ← nothing is shown; sudo receives the real password
```

If the vault is locked, taciTTY asks for your master passphrase the first
time you use an alias. It then stays unlocked, for every terminal, until it
has been idle for 15 minutes.

## 📖 Commands

| Command | What it does |
|---|---|
| `tacitty init [--no-autostart]` | Create the vault, set the master passphrase, enable auto-start |
| `tacitty add <alias>` | Store a secret (typed hidden, confirmed twice) |
| `tacitty add <alias> --generate [--length N]` | Store a newly generated random secret |
| `tacitty rm <alias>` | Remove an alias |
| `tacitty mv <old> <new>` | Rename an alias |
| `tacitty ls` | List aliases and dates (never secrets) |
| `tacitty get <alias> [--force]` | Print a secret to stdout (refuses a terminal without `--force`) |
| `tacitty shell [-- <cmd> ...]` | Run your shell (or `<cmd>`) inside taciTTY |
| `tacitty enable` / `disable` | Turn auto-start on or off |
| `tacitty lock` / `unlock` / `status` | Lock, unlock or check the vault |
| `tacitty update [--check]` | Update to the latest release |
| `tacitty doctor` | Check that everything is set up correctly |
| `tacitty config` | Print the config file path |

Alias names: letters, digits, `.`, `_`, `/` and `-`, up to 64 characters,
starting with a letter or digit.

## 🛠️ Configuration

Optional. Create `~/.config/tacitty/config.toml`. Every field is shown here
with its default:

```toml
trigger = "@"               # the character that starts an alias
backend = "native"          # native | pass | secret-service | command
on_miss = "bell"            # unknown alias: bell | literal
idle_lock_minutes = 15      # lock the vault after this much inactivity
title_indicator = true      # show "tacitty: secret prompt" in the window title

[remote]
mode = "auto"               # auto | confirm | off
processes = ["ssh", "mosh-client", "telnet", "docker", "kubectl", "podman"]
prompt_regex = '(?i)\b(password|passphrase|passcode|pin)\b[^\n]*:\s*$'

[pass]
prefix = "tacitty"

[command]
get = "bw get password {alias}"
```

<details>
<summary><b>Backends: where secrets are stored</b></summary>
<br>

| Backend | Storage | Notes |
|---|---|---|
| **`native`** (default) | `~/.local/share/tacitty/vault.age` | One [`age`](https://github.com/str4d/rage)-encrypted file (scrypt passphrase), mode `0600`. A per-user background agent keeps it unlocked until the idle timeout, so you enter the passphrase once per session. |
| **`pass`** | [`pass`](https://www.passwordstore.org/) under `<prefix>/<alias>` | Read-only; manage entries with `pass` itself. |
| **`secret-service`** | GNOME Keyring / KWallet via `secret-tool` | `tacitty add` can write here too. |
| **`command`** | Any command you configure | `{alias}` is substituted, the first line of output is the secret. Run directly, never through a shell, so alias text can't inject commands. |

Helper programs (`pass`, `secret-tool`, `command`) run without access to
your terminal and are stopped after 30 seconds, so they can't prompt you
for anything. Unlock their stores beforehand if they need it (for example
`bw unlock` for Bitwarden). Secrets containing control characters are
refused from every backend.

</details>

## 📚 Documentation

The [taciTTY guide](docs/GUIDE.md) covers everything else:

- [**Install**](docs/GUIDE.md#install): the installer, verifying downloads, updating
- [**How it works**](docs/GUIDE.md#how-it-works): how password prompts are detected, locally and over SSH
- [**Auto-start**](docs/GUIDE.md#auto-start): what `tacitty init` changes, and how to switch it off
- [**Security**](docs/GUIDE.md#security): threat model, protections and known limitations
- [**Development**](docs/GUIDE.md#development): building, testing and releasing

<a id="license"></a>

## 📄 License

taciTTY is free and open source, licensed under either of

- [MIT license](LICENSE-MIT), or
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option. You can use it anywhere, including at work and in
commercial settings.

Unless you explicitly state otherwise, any contribution you intentionally
submit for inclusion in taciTTY, as defined in the Apache-2.0 license, is
dual-licensed as above, without any additional terms or conditions.

## 🤖 AI disclosure

All of taciTTY's code, tests and documentation were written by
[Claude](https://claude.com/claude-code), under the direction of the
project's author, who designed it, made its decisions, and is responsible
for it.
