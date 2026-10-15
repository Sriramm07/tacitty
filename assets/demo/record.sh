#!/bin/sh
# Re-record assets/demo.gif. Run from the repository root:
#
#   cargo build --release --target x86_64-unknown-linux-musl
#   sh assets/demo/record.sh
#
# Two throwaway containers on a private Docker network:
#   - "db-prod" (10.42.0.15): sshd + PostgreSQL, see server/Dockerfile
#   - the "laptop": VHS + ssh client, running tacitty as user "sriram"
# All passwords are demo values. Nothing on the host is touched except
# assets/demo.gif; the containers and network are removed afterwards.
set -eu

BIN="target/x86_64-unknown-linux-musl/release/tacitty"
[ -x "$BIN" ] || { echo "build $BIN first (see above)" >&2; exit 1; }

NET=tacitty-demo
SERVER=tacitty-demo-server

docker build -q -t tacitty-demo-server assets/demo/server >/dev/null
docker build -q -t tacitty-demo-vhs assets/demo/client >/dev/null

cleanup() {
    docker rm -f "$SERVER" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create --subnet 10.42.0.0/24 "$NET" >/dev/null
docker run -d --rm --name "$SERVER" --hostname db-prod \
    --network "$NET" --ip 10.42.0.15 tacitty-demo-server >/dev/null

docker run --rm --hostname laptop --network "$NET" \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -v "$PWD:/vhs" \
    -v "$PWD/$BIN:/usr/local/bin/tacitty:ro" \
    --entrypoint bash \
    tacitty-demo-vhs -c '
set -e
useradd -m -s /bin/bash sriram
mkdir -p /home/sriram/.ssh
printf "Host *\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  LogLevel ERROR\n" \
    > /home/sriram/.ssh/config
chown -R sriram: /home/sriram/.ssh
# Short, readable local prompt for the recording.
echo "PS1='\''\[\e[38;5;117m\]sriram\[\e[0m\] \[\e[38;5;245m\]~\[\e[0m\] \$ '\''" >> /home/sriram/.bashrc
# Wait for the server to accept ssh connections.
for _ in $(seq 50); do (exec 3<>/dev/tcp/10.42.0.15/22) 2>/dev/null && break; sleep 0.2; done
vhs assets/demo/demo.tape
chown "$HOST_UID:$HOST_GID" assets/demo.gif
'
