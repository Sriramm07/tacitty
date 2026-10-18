# tacitty: start every interactive shell inside the tacitty wrapper.
#
# You normally don't need this file: `tacitty init` (or `tacitty enable`)
# adds the same block to ~/.bashrc / ~/.zshrc for you, and `tacitty disable`
# removes it. Use it only if you manage your shell startup files by hand.
# It's portable POSIX, so it works in ~/.bashrc and ~/.zshrc alike.
#
# Safe by design: it only runs for interactive shells on a terminal, can be
# skipped with NO_TACITTY=1, and if tacitty can't start (exit code 213) you
# get your normal shell instead of a terminal that closes immediately.
case $- in *i*)
  if [ -z "${TACITTY_ACTIVE:-}" ] && [ -z "${NO_TACITTY:-}" ] && [ -t 0 ] \
     && command -v tacitty >/dev/null 2>&1; then
    tacitty shell --autostart
    __tacitty_rc=$?
    if [ "$__tacitty_rc" -ne 213 ]; then exit "$__tacitty_rc"; fi
    unset __tacitty_rc
  fi
;; esac
