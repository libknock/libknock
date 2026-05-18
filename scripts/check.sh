#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  mapfile -t go_files < <(git ls-files '*.go' ':!:vendor/**')
else
  mapfile -t go_files < <(find . -name '*.go' -not -path './vendor/*' -print | sort)
fi

echo "== gofmt (non-vendor) =="
if ((${#go_files[@]})); then
  if out=$(gofmt -l "${go_files[@]}") && [[ -n "$out" ]]; then
    echo "$out"
    echo "gofmt differences found" >&2
    exit 1
  fi
fi

echo "== core tests =="
go test -count=1 ./...

echo "== vet =="
go vet ./...

echo "== race smoke =="
go test -race -count=1 ./auth ./firewall ./gate ./knock ./netx ./policy ./protocol ./relay

echo "== nested modules =="
go -C observability/prometheus test -count=1 ./...
go -C observability/prometheus vet ./...
go -C test/integration/grpc test -count=1 ./...
go -C test/integration/grpc vet ./...

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "== diff whitespace =="
  git diff --check
fi

echo "ok"
