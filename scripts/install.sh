#!/bin/sh
# Install the webmcp daemon from its GitHub release.
#   curl -fsSL https://webmcp.fast/install.sh | sh
# Environment: WEBMCP_VERSION (default: latest), WEBMCP_INSTALL_DIR (default: ~/.local/bin).
# It downloads one tarball and its checksum over HTTPS, verifies the checksum,
# and copies one binary. It never uses sudo and changes nothing else.
set -eu

REPO="proticom/webmcp"
VERSION="${WEBMCP_VERSION:-latest}"
DIR="${WEBMCP_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }
need curl
need tar
need uname

case "$(uname -s)" in
  Darwin) os="apple-darwin" ;;
  Linux) os="unknown-linux-gnu" ;;
  *) die "unsupported OS: $(uname -s). Build from source: https://github.com/$REPO" ;;
esac
case "$(uname -m)" in
  arm64 | aarch64) arch="aarch64" ;;
  x86_64 | amd64) arch="x86_64" ;;
  *) die "unsupported CPU: $(uname -m)" ;;
esac
target="$arch-$os"

if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
    sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
  [ -n "$VERSION" ] || die "could not find the latest release"
fi

name="webmcp-$VERSION-$target"
base="https://github.com/$REPO/releases/download/$VERSION"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading $name"
curl -fsSL "$base/$name.tar.gz" -o "$tmp/$name.tar.gz" || die "no release asset for $target at $VERSION"
curl -fsSL "$base/$name.tar.gz.sha256" -o "$tmp/$name.tar.gz.sha256" || die "checksum file missing"

want=$(cut -d' ' -f1 <"$tmp/$name.tar.gz.sha256")
if command -v shasum >/dev/null 2>&1; then
  got=$(shasum -a 256 "$tmp/$name.tar.gz" | cut -d' ' -f1)
elif command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/$name.tar.gz" | cut -d' ' -f1)
else
  die "need shasum or sha256sum to verify the download"
fi
[ "$want" = "$got" ] || die "checksum mismatch: expected $want, got $got"

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
mkdir -p "$DIR"
cp "$tmp/$name/webmcp" "$DIR/webmcp"
chmod 755 "$DIR/webmcp"

say "Installed $("$DIR/webmcp" --version) to $DIR/webmcp"
case ":$PATH:" in
  *":$DIR:"*) ;;
  *) say "Add it to your PATH:  export PATH=\"$DIR:\$PATH\"" ;;
esac
say "Next:  webmcp up"
