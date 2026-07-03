#!/bin/sh
# Publish Tidegate to crates.io and npm.
#
# Prerequisites (irreducibly user-only — they require your credentials):
#   cargo login <crates.io token>     # https://crates.io/settings/tokens
#   npm login                         # or set a valid ~/.npmrc authToken
#
# Then: sh scripts/publish.sh
set -e
cd "$(dirname "$0")/.."

echo "==> crates.io (in dependency order)"
# Leaf crates first; wait for the index to see each before publishing dependents.
cargo publish -p tidegate-policy
sleep 20
cargo publish -p tidegate-vault
sleep 20
cargo publish -p tidegate-daemon
sleep 20
cargo publish -p tidegate

echo "==> npm (wrapper that fetches the release binary)"
( cd npm && npm publish --access public )

echo "Done. Verify:"
echo "  cargo install tidegate"
echo "  npm install -g tidegate"
