<div align="center">

# 🔐 taciTTY

**Password aliases for your terminal.**<br>
Type `@proddb` at any password prompt and the real secret is sent instead.

[![Release](https://img.shields.io/github/v/release/Sriramm07/tacitty?color=8b5cf6)](https://github.com/Sriramm07/tacitty/releases/latest)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-0ea5e9)](docs/GUIDE.md#install)
[![Rust](https://img.shields.io/badge/built%20with-Rust-f97316)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-64748b)](#license)

<img src="https://raw.githubusercontent.com/Sriramm07/tacitty/main/assets/demo.gif" alt="tacitty demo: save a password as @admin, ssh to a server with @admin (unlocking the vault on first use), become root with @root, then open PostgreSQL with @pgdb" width="860">

</div>

---

## ✨ Why taciTTY?

Long, random passwords are safe but painful to type. Copy-pasting them leaks
them into clipboard managers, and typing them invites typos and shoulder
surfers. taciTTY lets you type a short, memorable alias instead. It works at
**any** terminal password prompt: `sudo`, `su`, `ssh`, `psql`, `mysql`,
`gpg`, `read -s`, Python's `getpass` and more.

- 🎯 **Only at password prompts.** Type `@proddb` in a normal shell
  line, in `vim` or in `less`, and it stays plain text.
- 🔒 **Local and encrypted.** Secrets live in an
  [`age`](https://github.com/str4d/rage)-encrypted vault on your machine.
  Unlock it once and it locks itself again after 15 minutes of inactivity.
- 🙈 **Nothing to snoop on.** No clipboard, no keystroke injection, no
  global keyboard hooks, and nothing in your shell history or scrollback.
- 🌐 **Works over SSH too.** Prompts from remote hosts inside `ssh`,
  `mosh`, `docker exec` or `kubectl exec` sessions are recognised as well.
- 🧩 **Works inside tmux and screen.** Every pane is wrapped automatically,
  with no configuration.
- ⚡ **Quick to set up.** One self-contained binary. `tacitty init` turns it
  on for every new terminal automatically.

> 🤨 **Skeptical? Good. You should be.** A tool that sits between your
> keyboard and your passwords deserves hard questions.
> **[Is this safe? (the FAQ for the suspicious) →](docs/FAQ.md)**

## 🚀 Quick start

```sh
# 1. Install (Linux or macOS, x86_64 or ARM64, no root needed)
curl -fsSL https://raw.githubusercontent.com/Sriramm07/tacitty/main/install.sh | sh
# …or with Homebrew (macOS/Linux):
brew install Sriramm07/tap/tacitty
# …or with Cargo (builds from source; needs the Rust toolchain):
cargo install tacitty

# 2. Create your vault and turn on auto-start
tacitty init

# 3. Save a secret under an alias
tacitty add proddb
```

Open a new terminal — auto-start wraps it for you — and use it at any
password prompt:

```console
$ sudo systemctl restart nginx
[sudo] password for sriram: @proddb⏎     ← nothing is shown; sudo receives the real password
```

> To start taciTTY in your **current** terminal immediately — for example
> right after installing or upgrading — run `tacitty shell`. New terminals
> pick it up automatically.

If the vault is locked, taciTTY asks for your master passphrase the first
time you use an alias. It then stays unlocked, for every terminal, until it
has been idle for 15 minutes.

Is one of your *real* passwords starting with `@`? Type `@@` for a literal
`@` at a prompt: `@@Summer2024` sends `@Summer2024` exactly as typed.

## 📖 Commands

| Command | What it does |
|---|---|
| `tacitty init [--no-autostart]` | Create the vault, set the master passphrase, enable auto-start |
| `tacitty add <alias> [-g <group>]` | Store a secret (typed hidden, confirmed twice), optionally in a group |
| `tacitty add <alias> --generate [--length N]` | Store a newly generated random secret |
| `tacitty rm <alias>` | Remove an alias |
| `tacitty mv <old> <new>` | Rename an alias (it stays in its group) |
| `tacitty ls [-g <group>]` | List aliases and dates by group (never secrets) |
| `tacitty group ls` | List groups and how many aliases each holds |
| `tacitty group move <alias> ... --to <group>` | Move aliases into a group |
| `tacitty group rename <old> <new>` | Rename a group |
| `tacitty group rm <group>` | Delete a group (its aliases move to the default group) |
| `tacitty group default [<group>]` | Show or set the group new aliases go into |
| `tacitty get <alias> [--force]` | Print a secret to stdout (refuses a terminal without `--force`) |
| `tacitty run [--] <cmd> [args ...]` | Run `<cmd>`, replacing `@alias` arguments with the real secret (keeps it out of history/scrollback; see [the note on `ps`](docs/GUIDE.md#run)) |
| `tacitty export [<alias> ...] [-g <group>] -o <file> [--with-key <key or file>] [--armor]` | Write aliases to an encrypted file to share with colleagues (protected by a passphrase, or by their age/SSH public keys) |
| `tacitty import <file> [-i <identity>] [-g <group>] [--overwrite]` | Add the aliases from an export file to your vault |
| `tacitty shell [-- <cmd> ...]` | Run your shell (or `<cmd>`) inside taciTTY |
| `tacitty enable` / `disable` | Turn auto-start on or off |
| `tacitty lock` / `unlock` / `status` | Lock, unlock or check the vault |
| `tacitty update [--check]` | Update to the latest release |
| `tacitty doctor` | Check that everything is set up correctly |
| `tacitty config` | Print the config file path |
| `tacitty completions <bash\|zsh\|fish>` | Print a shell completion script to stdout |
| `tacitty man` | Print the man page (roff) to stdout |

Alias names: letters, digits, `.`, `_`, `/` and `-`, up to 64 characters,
starting with a letter or digit. Group names follow the same rules,
without `/`. `-g` / `--group` can be repeated for `export`.

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
| **`secret-service`** | GNOME Keyring / KWallet via `secret-tool` | Linux only. `tacitty add` can write here too. |
| **`command`** | Any command you configure | `{alias}` is substituted, the first line of output is the secret. Run directly, never through a shell, so alias text can't inject commands. |

Helper programs (`pass`, `secret-tool`, `command`) run without access to
your terminal and are stopped after 30 seconds, so they can't prompt you
for anything. Unlock their stores beforehand if they need it (for example
`bw unlock` for Bitwarden). Secrets containing control characters are
refused from every backend.

</details>

## 📚 Documentation

The [taciTTY guide](docs/GUIDE.md) covers everything else:

- [**Is this safe?**](docs/FAQ.md): straight answers for the suspicious
- [**Install**](docs/GUIDE.md#install): the installer, verifying downloads, updating
- [**How it works**](docs/GUIDE.md#how-it-works): how password prompts are detected, locally and over SSH
- [**Auto-start**](docs/GUIDE.md#auto-start): what `tacitty init` changes, and how to switch it off
- [**Groups**](docs/GUIDE.md#groups): organising aliases (for example a `prod` group) for listing and sharing
- [**Running a command with an alias**](docs/GUIDE.md#run): `tacitty run` for tools that only take a password on the command line, and what it does and doesn't hide
- [**Sharing aliases securely**](docs/GUIDE.md#sharing): giving colleagues the same aliases with `tacitty export` / `import`
- [**Security**](docs/GUIDE.md#security): threat model, protections and known limitations
- [**Shell completions and man page**](docs/GUIDE.md#completions): tab-completion for bash/zsh/fish, and `man tacitty`
- [**Development**](docs/GUIDE.md#development): building, testing and releasing

<a id="license"></a>

## 📄 License

taciTTY is free and open source, licensed under either of

- [MIT license](LICENSE-MIT), or
- [Apache License, Version 2.0](LICENSE-APACHE)

---

<sub>Built with AI assistance (Claude).</sub>
