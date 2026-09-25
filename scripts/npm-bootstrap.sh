#!/bin/sh
# One-time npm setup for @proticom/webmcp, run by a maintainer who is logged in
# to npm (`npm login`, 2FA on). Safe to rerun: existing packages are skipped and
# trust is only added where missing.
#
#   1. Publishes a 0.0.0 placeholder of each package name, because npm cannot
#      attach a trusted publisher to a name that does not exist yet.
#   2. Trusts GitHub Actions (proticom/webmcp, release.yml, environment
#      "release") to publish each package, so releases need no npm token.
#
# Afterwards, on npmjs.com set each package to "Require two-factor
# authentication and disallow tokens" (Settings -> Publishing access).
set -eu

REPO="proticom/webmcp"
WORKFLOW="release.yml"
ENVIRONMENT="release"
PACKAGES="@proticom/webmcp @proticom/webmcp-darwin-arm64 @proticom/webmcp-darwin-x64 @proticom/webmcp-linux-x64 @proticom/webmcp-linux-arm64 @proticom/webmcp-win32-x64"

who=$(npm whoami 2>/dev/null) || { echo "Not logged in to npm. Run: npm login" >&2; exit 1; }
echo "npm user: $who"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

for pkg in $PACKAGES; do
  if npm view "$pkg" version >/dev/null 2>&1; then
    echo "exists:    $pkg"
  else
    dir="$tmp/$(echo "$pkg" | tr '/@' '__')"
    mkdir -p "$dir"
    cat >"$dir/package.json" <<JSON
{
  "name": "$pkg",
  "version": "0.0.0",
  "description": "Placeholder reserving the name for the webmcp daemon. Install @proticom/webmcp.",
  "license": "Apache-2.0",
  "repository": { "type": "git", "url": "git+https://github.com/$REPO.git" },
  "homepage": "https://webmcp.fast"
}
JSON
    printf '# %s\n\nPlaceholder. The real package is published from https://github.com/%s.\n' "$pkg" "$REPO" >"$dir/README.md"
    (cd "$dir" && npm publish --access public)
    echo "published: $pkg@0.0.0"
  fi
done

# `npm trust list` needs its own 2FA approval and its output cannot be trusted
# as a "done" signal, so always ask npm to add the relationship; it refuses a
# duplicate, which is fine on a rerun.
for pkg in $PACKAGES; do
  if npm trust github "$pkg" --file "$WORKFLOW" --repository "$REPO" --environment "$ENVIRONMENT" --yes; then
    echo "trusted:   $pkg -> $REPO/$WORKFLOW ($ENVIRONMENT)"
  else
    echo "not added: $pkg (already trusted, or npm refused; see the message above)" >&2
  fi
done

echo
echo "Done. Last manual step: on npmjs.com, for each package, Settings -> Publishing access ->"
echo "\"Require two-factor authentication and disallow tokens\"."
