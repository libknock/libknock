#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

snapshot=${1:-docs/api-surface.md}
current=$(mktemp)
go run scripts/api_snapshot.go . > "$current"

expected=$(mktemp)
trap 'rm -f "$current" "$expected"' EXIT
awk '
  /^```api-signature-snapshot root$/ {inblock=1; next}
  /^```$/ && inblock {inblock=0; next}
  inblock {print}
' "$snapshot" > "$expected"

if [[ ! -s "$expected" ]]; then
  awk '
    /^```api-snapshot root$/ {inblock=1; next}
    /^```$/ && inblock {inblock=0; next}
    inblock {print}
  ' "$snapshot" | while IFS= read -r symbol; do
    [[ -z "$symbol" ]] && continue
    if ! grep -Eq "^(const|func|type|var) ${symbol}([ (]|$)" "$current"; then
      echo "missing stable root export: $symbol" >&2
      exit 1
    fi
  done
  echo "api-check: ok (symbol snapshot)"
  exit 0
fi

if ! diff -u "$expected" "$current"; then
  echo "stable root API signature snapshot drifted; update docs/api-surface.md deliberately" >&2
  exit 1
fi

echo "api-check: ok"
