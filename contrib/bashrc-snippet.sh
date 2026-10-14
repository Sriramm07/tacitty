# tacitty: launch the PTY wrapper automatically for interactive shells.
# Add this to ~/.bashrc (or ~/.zshrc — it's portable POSIX). The
# TACITTY_ACTIVE guard is redundant with tacitty's own nesting guard, but
# checking it here too avoids even spawning a child process that would
# just exec straight back out again.
if [ -z "$TACITTY_ACTIVE" ] && [ -t 0 ] && command -v tacitty >/dev/null 2>&1; then
    exec tacitty shell
fi
