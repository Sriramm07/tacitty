#!/bin/sh
# Re-record assets/demo.gif. Run from the repository root:
#
#   cargo build --release --target x86_64-unknown-linux-musl
#   sh assets/demo/record.sh
#
# Everything runs inside the VHS container: a throwaway non-root user
# ("sriram") is created, and root gets a demo password so `su -` shows a real
# password prompt. Nothing on the host is touched except assets/demo.gif.
set -eu

BIN="target/x86_64-unknown-linux-musl/release/tacitty"
[ -x "$BIN" ] || { echo "build $BIN first (see above)" >&2; exit 1; }

docker run --rm --hostname demo \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -v "$PWD:/vhs" \
    -v "$PWD/$BIN:/usr/local/bin/tacitty:ro" \
    --entrypoint bash \
    ghcr.io/charmbracelet/vhs:v0.10.0 -c '
set -e
useradd -m -s /bin/bash sriram
echo "root:correct-horse-42" | chpasswd
# Short, readable prompts for the recording.
echo "PS1='\''\[\e[38;5;117m\]sriram\[\e[0m\] \[\e[38;5;245m\]~\[\e[0m\] \$ '\''" >> /home/sriram/.bashrc
echo "PS1='\''\[\e[38;5;210m\]root\[\e[0m\] \[\e[38;5;245m\]~\[\e[0m\] # '\''" >> /root/.bashrc
vhs assets/demo/demo.tape
chown "$HOST_UID:$HOST_GID" assets/demo.gif
'
