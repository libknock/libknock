#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

echo "== standard checks =="
scripts/check.sh

echo "== build main module =="
go build ./...

echo "== short fuzz smoke =="
go test ./protocol -run=^$ -fuzz=FuzzEnvelopeV2Open -fuzztime=10s
go test ./knock -run=^$ -fuzz=FuzzOpenKnockFrame -fuzztime=10s
go test ./auth -run=^$ -fuzz=FuzzServerAuthMalformedInput -fuzztime=10s

echo "== benchmark smoke =="
go test -run=^$ -bench=. -benchtime=1x ./auth ./protocol ./knock ./policy ./gate

echo "== docs link smoke =="
python3 scripts/check-doc-links.py

echo "== license/dependency smoke =="
test -f LICENSE
test -f NOTICE
test -f go.mod
test -f go.sum
go list -m all >/dev/null

echo "release-check: ok"
