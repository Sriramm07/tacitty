#!/bin/sh
# tacitty installer: downloads a prebuilt binary (Linux or macOS) from GitHub Releases,
# verifies its SHA-256 checksum, and installs it.
#
#   curl -fsSL https://raw.githubusercontent.com/Sriramm07/tacitty/main/install.sh | sh
#
# Environment:
#   TACITTY_VERSION       release tag to install (default: latest, e.g. v0.1.0)
#   TACITTY_INSTALL_DIR   where to put the binary (default: ~/.local/bin)

set -eu

# Portability: plain POSIX sh, and only options that the GNU (Linux) and
# BSD (macOS) versions of curl, sed, cut, tail, tr, mktemp and tar share.

# Everything runs inside main(), called on the last line: if the download
# of this script is cut off part-way, the shell has only read a function
# definition and runs nothing.
main() {
    REPO="Sriramm07/tacitty"
    INSTALL_DIR="${TACITTY_INSTALL_DIR:-$HOME/.local/bin}"

    say() { printf 'tacitty-install: %s\n' "$*"; }
    die() { printf 'tacitty-install: error: %s\n' "$*" >&2; exit 1; }

    # HTTPS only, including on redirects.
    if command -v curl >/dev/null 2>&1; then
        fetch() { curl --proto '=https' --proto-redir '=https' -fsSL -o "$2" "$1"; }
        final_url() { curl --proto '=https' --proto-redir '=https' -fsSLI -o /dev/null -w '%{url_effective}' "$1"; }
    elif command -v wget >/dev/null 2>&1; then
        # wget's --https-only doesn't cover redirects, so follow the chain
        # ourselves: every hop must be HTTPS, then fetch the final address
        # with redirects turned off.
        final_url() {
            hops="$(wget -q -S --spider "$1" 2>&1 | sed -n 's/^ *[Ll]ocation: *//p' | tr -d '\r')" ||
                return 1
            for hop in $hops; do
                case "$hop" in https://*) ;; *) die "refusing a non-HTTPS redirect: $hop" ;; esac
            done
            last="$(printf '%s\n' "$hops" | tail -1)"
            if [ -n "$last" ]; then printf '%s' "$last"; else printf '%s' "$1"; fi
        }
        fetch() {
            target="$(final_url "$1")" || return 1
            wget -q --max-redirect=0 -O "$2" "$target"
        }
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

    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        Linux)
            case "$arch" in
                x86_64 | amd64) target="x86_64-unknown-linux-musl" ;;
                aarch64 | arm64) target="aarch64-unknown-linux-musl" ;;
                *) die "no prebuilt binary for $arch; build from source instead (see README)" ;;
            esac
            ;;
        Darwin)
            # A shell running under Rosetta reports x86_64 on Apple
            # Silicon; install the native build anyway.
            if [ "$arch" = "x86_64" ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null)" = "1" ]; then
                arch="arm64"
            fi
            case "$arch" in
                arm64 | aarch64) target="aarch64-apple-darwin" ;;
                x86_64) target="x86_64-apple-darwin" ;;
                *) die "no prebuilt binary for $arch; build from source instead (see README)" ;;
            esac
            ;;
        *) die "tacitty supports Linux and macOS only (found $os)" ;;
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
    # Install under a fresh, exclusively created temp name and rename, so
    # shells already running an older tacitty never see a half-written file
    # and nothing can be waiting at the temp path.
    staged="$(mktemp "$INSTALL_DIR/.tacitty.XXXXXXXX")"
    cat "$tmp/$name/tacitty" > "$staged"
    chmod 755 "$staged"
    mv -f "$staged" "$INSTALL_DIR/tacitty"
    say "installed $version to $INSTALL_DIR/tacitty"

    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *)
            if [ "$os" = "Darwin" ]; then
                # macOS never adds ~/.local/bin to PATH by itself.
                say "note: $INSTALL_DIR is not on your PATH; add it in your shell's startup file,"
                say "      e.g. echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.zshrc"
            else
                say "note: $INSTALL_DIR is not on your PATH yet; open a new terminal or add it"
            fi
            ;;
    esac

    echo
    echo "Next: run '$INSTALL_DIR/tacitty init' to create your vault and turn on"
    echo "auto-start, then 'tacitty add <alias>' to store your first secret."
}

main "$@"
