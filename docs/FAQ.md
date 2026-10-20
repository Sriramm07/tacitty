# Is this safe? (FAQ for the suspicious)

[← Back to the README](../README.md)

A program that sits between your keyboard and your passwords *should* make
you suspicious. Here are the hard questions, answered straight. The details
behind every answer are in the [Security section of the guide](GUIDE.md#security).

---

### Isn't this just a keylogger with good manners?

It does see what you type, the same way your terminal does: taciTTY runs
your shell inside a pseudo-terminal it controls, so every keystroke passes
through it. The difference is in what it does with them:

- It **stores nothing** you type. It only looks for `@alias` at the start of
  a line, and only while the terminal is hiding input (a password prompt).
- It **logs nothing** you type. The optional log (`TACITTY_LOG`) can only
  record fixed labels like `agent: unlocked`; the code can't log your input,
  because the logging function only accepts compile-time constant strings.
- It **sends nothing anywhere**. See the next question.

### Does it phone home?

No. taciTTY has no telemetry and makes no network connections, with one
exception you trigger yourself: `tacitty update` downloads the latest
release from GitHub over HTTPS. (Helper programs you configure as backends,
such as `pass` or Bitwarden's `bw`, may of course do their own thing.)

### Where do my passwords live?

In `~/.local/share/tacitty/vault.age`: one file, encrypted with
[age](https://age-encryption.org) using your master passphrase (scrypt),
readable only by you (`0600`). taciTTY refuses to open it if other users
can read it. Nothing is ever written to disk unencrypted.

While unlocked, the decrypted vault is held in memory by a small background
agent, which locks itself again after 15 minutes without use (or right
away with `tacitty lock`).

### Could `@proddb` get sent to the wrong place?

taciTTY only replaces an alias while the terminal is in password mode
(input hidden, read line by line), which is what `sudo`, `ssh`, `psql` and
friends do. In a normal shell line, in `vim`, in `less` or in a chat app,
`@proddb` stays plain text.

It also re-checks at the moment of sending. If the prompt disappeared while
you were typing the alias (you pressed Ctrl-C, it timed out, the program
exited), nothing is sent, and you see
`the password prompt changed, so nothing was sent`.

One honest caveat: any program that switches echo off and reads a line
gets the secret, whether or not it's a "real" password prompt. So only type
an alias where you actually mean to enter that password.

### What about prompts on a remote server over SSH?

Inside `ssh` (and `mosh`, `docker exec -it`, `kubectl exec -it`), taciTTY
can't see the remote terminal, so it uses a careful guess: the program in
front is one of those, your local terminal isn't showing what you type,
and the last line on screen ends like a password prompt. A malicious server
could print a fake prompt, but it still only gets a secret if **you** type
an alias there. If that worries you, set `remote.mode = "confirm"` to be
asked first, or `"off"` to disable it.

### My real password starts with `@`. Now what?

Type `@@` for a literal `@`: `@@Summer2024` sends `@Summer2024` exactly as
typed.

### What if malware is running as my user?

Then it's game over for most password tools, taciTTY included, and we say
so. Something running as you can, for example, ask the agent for secrets
while the vault is unlocked (the same trust boundary as `ssh-agent`).
taciTTY makes some attacks harder: it refuses core dumps and debugger
attachment, wipes secrets from memory after use, and checks that only your
user can talk to the agent. But it can't defend against your own account
being compromised, and neither can anything else at this level.

### Who checked all this?

The code has been through several security reviews during development
(AI-assisted audits, each followed by fixes and a verification pass), and
it has a large automated test suite that runs real password prompts through
real terminals on Linux and macOS. **It has not had an independent
third-party audit.** If you're a security person and find something,
please open an issue.

### Can I verify the download?

Yes. Every release archive comes with a SHA-256 checksum (checked
automatically by the installer and `tacitty update`) and a signed GitHub
build-provenance attestation, which proves it was built from this
repository by its release workflow:

```sh
gh attestation verify tacitty-v0.1.0-x86_64-unknown-linux-musl.tar.gz --repo Sriramm07/tacitty
```

Or build it yourself from source: see
[Development](GUIDE.md#development).

### What if taciTTY crashes or breaks?

It fails closed and gets out of your way. If the wrapper can't start, your
terminal opens your normal shell instead (with a warning), so it can never
lock you out. Your terminal settings are restored when it exits, and
nothing is sent unless every check passes.

### I forgot my master passphrase.

Then the vault can't be opened. There's no backdoor and no recovery: that's
the point of encryption. Keep a copy of important passwords in your main
password manager, or an [export](GUIDE.md#sharing) protected by a
passphrase you won't forget.

### How do I get rid of it completely?

```sh
tacitty disable                     # stop new terminals from starting it
pkill -f 'tacitty agent'            # stop the background agent
rm ~/.local/bin/tacitty             # the program
rm -r ~/.local/share/tacitty        # your vault (this deletes your aliases!)
rm -r ~/.config/tacitty             # your config, if you created one
```

Open a new terminal and it's gone.
