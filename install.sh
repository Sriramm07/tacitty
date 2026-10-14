#!/bin/sh
# tacitty installer: downloads a prebuilt static binary from GitHub Releases,
# verifies its SHA-256 checksum, and installs it.
#
#   curl -fsSL https://raw.githubusercontent.com/Sriramm07/tacitty/main/install.sh | sh
#
# Environment:
#   TACITTY_VERSION       release tag to install (default: latest, e.g. v0.1.0)
#   TACITTY_INSTALL_DIR   where to put the binary (default: ~/.local/bin)

set -eu

REPO="Sriramm07/tacitty"
INSTALL_DIR="${TACITTY_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf 'tacitty-install: %s\n' "$*"; }
die() { printf 'tacitty-install: error: %s\n' "$*" >&2; exit 1; }

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL -o "$2" "$1"; }
    final_url() { curl -fsSLI -o /dev/null -w '%{url_effective}' "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q -O "$2" "$1"; }
    final_url() { wget -q -S --spider "$1" 2>&1 | sed -n 's/^ *[Ll]ocation: *//p' | tail -1 | tr -d '\r'; }
else
    die "need curl or wget"
fi

if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    die "need sha256sum or shasum to verify the download"
fi

[ "$(uname -s)" = "Linux" ] || die "tacitty only supports Linux (found $(uname -s))"

case "$(uname -m)" in
    x86_64 | amd64) target="x86_64-unknown-linux-musl" ;;
    aarch64 | arm64) target="aarch64-unknown-linux-musl" ;;
    *) die "no prebuilt binary for $(uname -m); build from source instead (see README)" ;;
esac

version="${TACITTY_VERSION:-}"
if [ -z "$version" ]; then
    # Follow the /releases/latest redirect instead of calling the API, which
    # is rate-limited for anonymous use.
    version="$(final_url "https://github.com/$REPO/releases/latest" | sed -n 's|.*/tag/||p')"
    [ -n "$version" ] || die "could not find the latest release of $REPO"
fi

name="tacitty-$version-$target"
base="https://github.com/$REPO/releases/download/$version"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $name"
fetch "$base/$name.tar.gz" "$tmp/$name.tar.gz" || die "download failed: $base/$name.tar.gz"
fetch "$base/$name.tar.gz.sha256" "$tmp/$name.tar.gz.sha256" || die "checksum download failed"

expected="$(cut -d' ' -f1 "$tmp/$name.tar.gz.sha256")"
actual="$(sha256 "$tmp/$name.tar.gz")"
[ "$expected" = "$actual" ] || die "checksum mismatch (expected $expected, got $actual)"
say "checksum verified"

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
mkdir -p "$INSTALL_DIR"
# Install under a temp name and rename, so shells already running an older
# tacitty never see a half-written file.
cp "$tmp/$name/tacitty" "$INSTALL_DIR/.tacitty.new"
chmod 755 "$INSTALL_DIR/.tacitty.new"
mv -f "$INSTALL_DIR/.tacitty.new" "$INSTALL_DIR/tacitty"
say "installed $version to $INSTALL_DIR/tacitty"

case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) say "note: $INSTALL_DIR is not on your PATH yet; open a new terminal or add it" ;;
esac

echo
echo "Next: run '$INSTALL_DIR/tacitty init' to create your vault and turn on"
echo "auto-start, then 'tacitty add <alias>' to store your first secret."
