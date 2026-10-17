# tacitty demo. Re-record with: sh assets/demo/record.sh
Output assets/demo.gif

Require tacitty
Require ssh

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 18
Set Width 1280
Set Height 840
Set Padding 26
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set BorderRadius 10
Set TypingSpeed 70ms

# Off camera: become the demo user, create the vault and two aliases
# (@root, @pgdb), then open a new shell, which auto-starts tacitty. Each
# `add` locks the vault again; @admin is added on camera below.
Hide
Type "su - sriram" Enter
Sleep 800ms
Type "tacitty init" Enter
Wait+Screen /New master passphrase/
Type "my vault passphrase" Enter
Wait+Screen /Confirm master passphrase/
Type "my vault passphrase" Enter
Wait+Screen /store your first secret/
Type "clear; tacitty add root" Enter
Wait+Screen /Secret:/
Type "R00t-Pr0d-2026" Enter
Wait+Screen /Confirm secret:/
Type "R00t-Pr0d-2026" Enter
Wait+Screen /Master passphrase:/
Type "my vault passphrase" Enter
Wait+Screen /Saved @root/
Type "clear; tacitty add pgdb" Enter
Wait+Screen /Secret:/
Type "Pg-Pr0d-2026" Enter
Wait+Screen /Confirm secret:/
Type "Pg-Pr0d-2026" Enter
Wait+Screen /Master passphrase:/
Type "my vault passphrase" Enter
Wait+Screen /Saved @pgdb/
Type "bash" Enter
Sleep 1s
Type "clear" Enter
Sleep 500ms
Show

Sleep 500ms
Type "# 1. Save a password under an alias (typed hidden)" Enter
Sleep 300ms
Type "tacitty add admin" Enter
Wait+Screen /Secret:/
Sleep 1.2s
Type "Adm1n-Ssh-2026" Enter
Wait+Screen /Confirm secret:/
Sleep 800ms
Type "Adm1n-Ssh-2026" Enter
Wait+Screen /Master passphrase:/
Sleep 1.2s
Type "my vault passphrase" Enter
Wait+Screen /Saved @admin/
Sleep 2.5s
Type "# @root and @pgdb were saved the same way" Enter
Sleep 2s
Type "clear" Enter
Sleep 500ms

Type "# 2. SSH in: type @admin at the password prompt (first use asks for your vault passphrase)" Enter
Sleep 300ms
Type "ssh admin@10.42.0.15" Enter
Wait+Screen /password:/
Sleep 1.8s
Type "@admin" Enter
Wait+Screen /unlock vault/
Sleep 1.2s
Type "my vault passphrase" Enter
Wait+Screen /admin@db-prod/
Sleep 3.2s

Type "# 3. Become root: @root" Enter
Sleep 300ms
Type "su -" Enter
Wait+Screen /Password:/
Sleep 1.8s
Type "@root" Enter
Wait+Screen /root@db-prod/
Sleep 3.2s

Type "# 4. Open the database as postgres: @pgdb" Enter
Sleep 300ms
Type "su - postgres" Enter
Wait+Screen /postgres@db-prod/
Sleep 500ms
Type "psql -h 127.0.0.1 -U postgres" Enter
Wait+Screen /Password for user postgres/
Sleep 1.8s
Type "@pgdb" Enter
Wait+Screen /postgres=#/
Sleep 2.2s
Type "\conninfo" Enter
Sleep 4.5s

# Back out to the laptop.
Type "\q" Enter
Wait+Line /postgres@db-prod/
Sleep 300ms
Type "exit" Enter
Wait+Line /root@db-prod/
Sleep 300ms
Type "exit" Enter
Wait+Line /admin@db-prod/
Sleep 300ms
Type "exit" Enter
Wait+Line /sriram/
Sleep 1.8s
Type "clear" Enter
Sleep 300ms

Type "# 5. Everywhere else, @admin is just text" Enter
Sleep 300ms
Type "echo @admin" Enter
Sleep 5s
