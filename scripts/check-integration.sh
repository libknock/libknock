#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  mapfile -t go_files < <(git ls-files '*.go' ':!:vendor/**')
else
  mapfile -t go_files < <(find . -name '*.go' -not -path './vendor/*' -print | sort)
fi
fmt=""
if ((${#go_files[@]})); then
  fmt=$(gofmt -l "${go_files[@]}")
fi
if [ -n "$fmt" ]; then
  echo "$fmt"
  exit 1
fi

go test ./...
go vet ./...
go test -race ./auth ./firewall ./knock ./netx ./policy ./protocol ./relay ./gate
python3 scripts/check-doc-links.py
