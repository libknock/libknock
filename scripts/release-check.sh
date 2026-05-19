#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

echo "== standard checks =="
bash scripts/check.sh

echo "== build main module =="
go build ./...

echo "== short fuzz smoke =="
go test ./protocol -run=^$ -fuzz=FuzzEnvelopeV2Open -fuzztime=20s -parallel=1 -timeout=60s
go test ./knock -run=^$ -fuzz=FuzzOpenKnockFrame -fuzztime=20s -parallel=1 -timeout=60s
go test ./auth -run=^$ -fuzz=FuzzServerAuthMalformedInput -fuzztime=20s -parallel=1 -timeout=60s

echo "== benchmark smoke =="
go test -run=^$ -bench=. -benchtime=1x ./auth ./protocol ./knock ./policy ./gate

echo "== docs link smoke =="
python3 scripts/check-doc-links.py

echo "== duplication scan =="
STRICT=1 bash scripts/check-duplication.sh .

echo "== license/dependency smoke =="
test -f LICENSE
test -f NOTICE
test -f go.mod
test -f go.sum
go list -m all >/dev/null

echo "release-check: ok"
