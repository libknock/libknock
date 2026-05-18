#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
stamp=${1:-$(date -u +%Y%m%dT%H%M%SZ)}
out="/tmp/libknock-${stamp}.zip"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/libknock"
git archive --format=tar HEAD | tar -C "$tmp/libknock" -xf -
rm -rf "$tmp/libknock/vendor"
find "$tmp/libknock" -type d -exec chmod 755 {} +
find "$tmp/libknock" -type f -exec chmod 644 {} +
find "$tmp/libknock/scripts" -type f -name '*.sh' -exec chmod 755 {} + 2>/dev/null || true
(cd "$tmp" && zip -qr "$out" libknock)
sha256sum "$out" > "$out.sha256"
echo "$out"
cat "$out.sha256"
