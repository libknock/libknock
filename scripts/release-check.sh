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
DUPL_THRESHOLD=120 STRICT=1 bash scripts/check-duplication.sh .

echo "== license/dependency smoke =="
test -f LICENSE
test -f NOTICE
test -f go.mod
test -f go.sum
go list -m all >/dev/null

echo "== vendor release smoke =="
go work vendor
test -f vendor/modules.txt
go test -mod=vendor ./...
go vet -mod=vendor ./...
go test -mod=vendor ./observability/prometheus/...
go test -mod=vendor ./test/integration/grpc/...
go test -mod=vendor ./examples/grpc-client/... ./examples/grpc-server/...
rm -rf vendor

echo "release-check: ok"
