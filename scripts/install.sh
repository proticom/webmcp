#!/bin/sh
# Install the webmcp daemon from its GitHub release.
#   curl -fsSL https://github.com/proticom/webmcp/releases/latest/download/install.sh | sh
# Environment: WEBMCP_VERSION (default: latest), WEBMCP_INSTALL_DIR (default: ~/.local/bin),
# WEBMCP_REQUIRE_ATTESTATION=1 (fail unless build provenance verifies).
# It downloads one tarball and the release's SHA256SUMS over HTTPS and verifies the checksum.
# If the GitHub CLI is installed and signed in, it also verifies the tarball's build provenance
# attestation: proof, signed through Sigstore, that this repo's release workflow built it.
# It copies one binary, never uses sudo and changes nothing else.
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
  Darwin)
    os="apple-darwin"
    # The release tarballs are not code-signed (no Apple Developer ID), so
    # Gatekeeper quarantines and blocks a binary downloaded this way. npm does
    # not quarantine what it installs, so that is the recommended route.
    if [ "${WEBMCP_ALLOW_UNSIGNED:-}" != "1" ]; then
      say "On macOS the recommended install is:"
      say "    npm i -g @proticom/webmcp    (or: npx @proticom/webmcp up)"
      say "The release tarballs are unsigned and Gatekeeper will block them."
      say "To install one anyway (then: xattr -d com.apple.quarantine $DIR/webmcp):"
      say "    curl -fsSL https://github.com/$REPO/releases/latest/download/install.sh | WEBMCP_ALLOW_UNSIGNED=1 sh"
      exit 0
    fi
    ;;
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
curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" || die "SHA256SUMS missing from release $VERSION"

want=$(awk -v f="$name.tar.gz" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
[ -n "$want" ] || die "no checksum for $name.tar.gz in SHA256SUMS"
if command -v shasum >/dev/null 2>&1; then
  got=$(shasum -a 256 "$tmp/$name.tar.gz" | cut -d' ' -f1)
elif command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/$name.tar.gz" | cut -d' ' -f1)
else
  die "need shasum or sha256sum to verify the download"
fi
[ "$want" = "$got" ] || die "checksum mismatch: expected $want, got $got"

# The checksum only catches a damaged download: SHA256SUMS comes from the same
# release. The attestation shows the file was built by this repo's workflow.
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  gh attestation verify "$tmp/$name.tar.gz" --repo "$REPO" >/dev/null 2>&1 ||
    die "build provenance did not verify for $name.tar.gz (releases before v0.3.0 have none)"
  say "Verified build provenance: built by $REPO's release workflow"
elif [ "${WEBMCP_REQUIRE_ATTESTATION:-}" = "1" ]; then
  die "WEBMCP_REQUIRE_ATTESTATION=1 needs the GitHub CLI (gh), signed in"
else
  say "Checksum verified. To also verify who built it, install the GitHub CLI and run:"
  say "    gh attestation verify $name.tar.gz --repo $REPO"
fi

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
