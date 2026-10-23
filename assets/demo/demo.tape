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
Set TypingSpeed 55ms

# Off camera: become the demo user with a clean prompt.
Hide
Type "su - sriram" Enter
Sleep 800ms
Type "clear" Enter
Sleep 300ms
Show

# 1. Set up the vault. The cyan banner shows once, on `tacitty init`.
Sleep 500ms
Type "tacitty init" Enter
Wait+Screen /New master passphrase/
Sleep 1.2s
Type "my vault passphrase" Enter
Wait+Screen /Confirm master passphrase/
Sleep 600ms
Type "my vault passphrase" Enter
Wait+Screen /store your first secret/
Sleep 1.8s
Type "clear" Enter
Sleep 400ms

# 2. Save a password under an alias (typed hidden).
Type "# Save a password under an alias" Enter
Sleep 200ms
Type "tacitty add admin" Enter
Wait+Screen /Secret:/
Sleep 900ms
Type "Adm1n-Ssh-2026" Enter
Wait+Screen /Confirm secret:/
Sleep 600ms
Type "Adm1n-Ssh-2026" Enter
Wait+Screen /Master passphrase:/
Sleep 900ms
Type "my vault passphrase" Enter
Wait+Screen /Saved @admin/
Sleep 1.8s
Type "# (@root and @pgdb saved the same way)" Enter
Sleep 1.5s

# Off camera: add the other two aliases, then open a fresh (auto-wrapped) shell.
Hide
Type "tacitty add root" Enter
Wait+Screen /Secret:/
Type "R00t-Pr0d-2026" Enter
Wait+Screen /Confirm secret:/
Type "R00t-Pr0d-2026" Enter
Wait+Screen /Master passphrase:/
Type "my vault passphrase" Enter
Wait+Screen /Saved @root/
Type "tacitty add pgdb" Enter
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
Sleep 300ms
Show

# 3. At a password prompt, type the alias (first use unlocks the vault).
Type "# At a password prompt, type the alias:" Enter
Sleep 200ms
Type "ssh admin@10.42.0.15" Enter
Wait+Screen /password:/
Sleep 1.4s
Type "@admin" Enter
Wait+Screen /unlock vault/
Sleep 1s
Type "my vault passphrase" Enter
Wait+Screen /admin@db-prod/
Sleep 2.4s

# 4. Become root: @root
Type "# Become root:" Enter
Sleep 200ms
Type "su -" Enter
Wait+Screen /Password:/
Sleep 1.2s
Type "@root" Enter
Wait+Screen /root@db-prod/
Sleep 2.4s

# 5. Open the database as postgres: @pgdb
Type "# Open the database:" Enter
Sleep 200ms
Type "su - postgres" Enter
Wait+Screen /postgres@db-prod/
Sleep 400ms
Type "psql -h 127.0.0.1 -U postgres" Enter
Wait+Screen /Password for user postgres/
Sleep 1.4s
Type "@pgdb" Enter
Wait+Screen /postgres=#/
Sleep 1.8s
Type "\conninfo" Enter
Sleep 3s
Type "\q" Enter
Wait+Line /postgres@db-prod/
Sleep 500ms

# 6. Everywhere else, the alias is just text.
Type "# Everywhere else, it's just text" Enter
Sleep 300ms
Type "echo @admin" Enter
Sleep 3.5s
