#!/bin/sh
# Tidegate installer. Downloads the platform binary from the latest GitHub
# release into ~/.tidegate/bin and prints a PATH hint.
#   curl -fsSL https://tidegate.dev/install.sh | sh
set -e

REPO="BlueprintLabIO/tidegate"
BINDIR="${TIDEGATE_BIN_DIR:-$HOME/.tidegate/bin}"

os="$(uname -s)"; arch="$(uname -m)"
case "$os" in
  Darwin) target_os="apple-darwin" ;;
  Linux)  target_os="unknown-linux-gnu" ;;
  *) echo "tidegate: unsupported OS $os. Build from source: cargo install tidegate"; exit 1 ;;
esac
case "$arch" in
  arm64|aarch64) target_arch="aarch64" ;;
  x86_64|amd64)  target_arch="x86_64" ;;
  *) echo "tidegate: unsupported arch $arch. Build from source: cargo install tidegate"; exit 1 ;;
esac
triple="${target_arch}-${target_os}"

ver="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep -m1 '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')"
[ -n "$ver" ] || { echo "tidegate: could not resolve latest release"; exit 1; }

url="https://github.com/$REPO/releases/download/$ver/tidegate-$triple.tar.gz"
echo "Downloading tidegate $ver ($triple)…"
mkdir -p "$BINDIR"
tmp="$(mktemp -d)"
curl -fsSL "$url" -o "$tmp/t.tar.gz"
tar -xzf "$tmp/t.tar.gz" -C "$BINDIR"
chmod +x "$BINDIR/tidegate"
rm -rf "$tmp"

echo "✔ installed to $BINDIR/tidegate"
case ":$PATH:" in
  *":$BINDIR:"*) ;;
  *) echo "  Add it to your PATH:  export PATH=\"$BINDIR:\$PATH\"" ;;
esac
echo "  Next:  tidegate connect github"
