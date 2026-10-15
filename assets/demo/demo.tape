# tacitty demo. Re-record with: sh assets/demo/record.sh
Output assets/demo.gif

Require tacitty

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 18
Set Width 1280
Set Height 600
Set Padding 26
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set BorderRadius 10
Set TypingSpeed 40ms

# Switch to the demo user off-camera.
Hide
Type "su - sriram" Enter
Sleep 800ms
Type "clear" Enter
Sleep 400ms
Show

Sleep 600ms
Type "# 1. Create your encrypted vault" Enter
Sleep 300ms
Type "tacitty init" Enter
Wait+Screen /New master passphrase/
Sleep 500ms
Type "my vault passphrase" Enter
Wait+Screen /Confirm master passphrase/
Sleep 300ms
Type "my vault passphrase" Enter
Wait+Screen /store your first secret/
Sleep 2.5s

Type "clear" Enter
Sleep 300ms
Type "# 2. Save the root password under an alias" Enter
Sleep 300ms
Type "tacitty add root-pw" Enter
Wait+Screen /Secret:/
Sleep 400ms
Type "correct-horse-42" Enter
Wait+Screen /Confirm secret:/
Sleep 300ms
Type "correct-horse-42" Enter
Wait+Screen /Master passphrase:/
Sleep 300ms
Type "my vault passphrase" Enter
Wait+Screen /Saved @root-pw/
Sleep 1.8s

Type "clear" Enter
Sleep 300ms
Type "# 3. Open a new terminal: tacitty is already running" Enter
Sleep 300ms
Type "bash" Enter
Sleep 1s

Type "# 4. At a real password prompt, type @root-pw (hidden, like any password)" Enter
Sleep 300ms
Type "su -" Enter
Wait+Screen /Password:/
Sleep 600ms
Type "@root-pw" Enter
Wait+Screen /unlock vault/
Sleep 600ms
Type "my vault passphrase" Enter
Wait+Screen /root .*#/
Sleep 500ms
Type "whoami" Enter
Sleep 1.6s
Type "exit" Enter
Sleep 600ms

Type "# 5. Anywhere else, @root-pw is just text" Enter
Sleep 300ms
Type "echo @root-pw" Enter
Sleep 3s
