#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

snapshot=${1:-docs/api-surface.md}
current=$(mktemp)
trap 'rm -f "$current"' EXIT

{ go doc -short .; go doc -short Server; go doc -short PeerInfo; } | awk '/^[[:space:]]*(const|func|type) /{print $2}' | sed 's/(.*//' | sed 's/=//' | sort -u > "$current"
missing=0
while IFS= read -r symbol; do
  [[ -z "$symbol" ]] && continue
  if ! grep -qxF "$symbol" "$current"; then
    echo "missing stable root export: $symbol" >&2
    missing=1
  fi
done < <(awk '
  /^```api-snapshot root$/ {inblock=1; next}
  /^```$/ && inblock {inblock=0; next}
  inblock {print}
' "$snapshot")

if [[ $missing -ne 0 ]]; then
  exit 1
fi

echo "api-check: ok"
