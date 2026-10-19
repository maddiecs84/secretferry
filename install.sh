#!/bin/sh
# Installs secretferry on Linux or macOS from a GitHub release.
#
#   curl -fsSL https://github.com/maddiecs84/secretferry/releases/latest/download/install.sh | sh
#
# To install a particular version, or somewhere else:
#
#   curl -fsSL .../install.sh | sh -s -- v0.1.0
#   curl -fsSL .../install.sh | SECRETFERRY_INSTALL_DIR=/usr/local/bin sh
#
# The archive is checked against the release's checksums.txt before anything is installed.
# Nothing here asks for a password or needs root: the default directory is ~/.local/bin.
set -eu

repo="maddiecs84/secretferry"
base="${SECRETFERRY_BASE_URL:-https://github.com/$repo/releases}"
version="${1:-${SECRETFERRY_VERSION:-}}"
dir="${SECRETFERRY_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
fail() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

# fetch URL FILE
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL -o "$2" "$1"; }
  final_url() { curl -fsSL -o /dev/null -w '%{url_effective}' "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
  final_url() { wget -q --max-redirect=10 --spider -S "$1" 2>&1 | sed -n 's/^ *Location: *//p' | tail -n 1; }
else
  fail "needs curl or wget"
fi

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "this script is for Linux and macOS; on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "no build for the $(uname -m) processor" ;;
esac

if [ -z "$version" ]; then
  # /releases/latest redirects to /releases/tag/<version>.
  version="$(final_url "$base/latest" | sed -n 's|.*/tag/||p')"
  [ -n "$version" ] || fail "could not find the latest release; is there one yet? Pass a version, such as v0.1.0"
fi
case "$version" in
  v[0-9]*) ;;
  *) fail "the version should look like v1.2.3" ;;
esac

name="secretferry_${version}_${os}_${arch}"
archive="$name.tar.gz"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

say "Downloading secretferry $version for $os/$arch"
fetch "$base/download/$version/$archive" "$work/$archive" || fail "could not download $archive from release $version"
fetch "$base/download/$version/checksums.txt" "$work/checksums.txt" || fail "could not download checksums.txt from release $version"

want="$(awk -v f="$archive" '$2 == f { print $1 }' "$work/checksums.txt")"
[ -n "$want" ] || fail "checksums.txt has no entry for $archive"
if command -v sha256sum >/dev/null 2>&1; then
  got="$(sha256sum "$work/$archive" | awk '{ print $1 }')"
elif command -v shasum >/dev/null 2>&1; then
  got="$(shasum -a 256 "$work/$archive" | awk '{ print $1 }')"
else
  fail "needs sha256sum or shasum to check the download"
fi
[ "$got" = "$want" ] || fail "the download does not match its checksum; nothing was installed"

tar -xzf "$work/$archive" -C "$work"
mkdir -p "$dir"
cp "$work/$name/secretferry" "$dir/secretferry.new"
chmod 755 "$dir/secretferry.new"
mv -f "$dir/secretferry.new" "$dir/secretferry"

say "Installed $dir/secretferry"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "Note: $dir is not on your PATH. Add it, for example:  export PATH=\"$dir:\$PATH\"" ;;
esac
