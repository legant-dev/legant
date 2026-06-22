#!/bin/sh
# Legant installer — download the latest release binary for your OS/arch.
#
#   curl -fsSL https://raw.githubusercontent.com/legant-dev/legant/main/install.sh | sh
#
# Env: LEGANT_VERSION=v0.1.0 (pin a version), LEGANT_INSTALL_DIR=/path (install dir).
set -eu

REPO="legant-dev/legant"
BIN="legant"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch="amd64" ;;
  aarch64 | arm64) arch="arm64" ;;
  *) echo "legant: unsupported architecture: $arch" >&2; exit 1 ;;
esac
case "$os" in
  linux | darwin) ;;
  *) echo "legant: unsupported OS: $os (on Windows, download from the releases page)" >&2; exit 1 ;;
esac

ver="${LEGANT_VERSION:-}"
if [ -z "$ver" ]; then
  ver=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep -m1 '"tag_name"' | cut -d'"' -f4)
fi
if [ -z "$ver" ]; then
  echo "legant: could not determine the latest version — set LEGANT_VERSION=vX.Y.Z" >&2
  exit 1
fi
vnum="${ver#v}"

url="https://github.com/$REPO/releases/download/$ver/legant_${vnum}_${os}_${arch}.tar.gz"
echo "legant: downloading $url"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$url" | tar -xz -C "$tmp"

dir="${LEGANT_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ]; then
    dir="/usr/local/bin"
  else
    dir="$HOME/.local/bin"
    mkdir -p "$dir"
  fi
fi
mv "$tmp/$BIN" "$dir/$BIN"
chmod +x "$dir/$BIN"

echo "legant: installed to $dir/$BIN"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "legant: add $dir to your PATH" ;;
esac
"$dir/$BIN" --version || true
echo
echo "Next:  legant guard install     # govern your coding agent in one command"
echo "       legant guard demo        # see it work (no setup)"
