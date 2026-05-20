#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

fmt=$(gofmt -l $(git ls-files '*.go' ':!:vendor/**'))
if [ -n "$fmt" ]; then
  echo "$fmt"
  exit 1
fi

go test ./...
go vet ./...
go test -race ./auth ./firewall ./knock ./netx ./policy ./protocol ./relay ./gate
python3 scripts/check-doc-links.py
