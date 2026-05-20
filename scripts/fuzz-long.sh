#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
fuzztime=${FUZZTIME:-10m}
parallel=${FUZZ_PARALLEL:-1}
timeout=${FUZZ_TIMEOUT:-15m}

echo "== protocol fuzz (${fuzztime}) =="
go test ./protocol -run=^$ -fuzz=FuzzDecodePayload -fuzztime="$fuzztime" -parallel="$parallel" -timeout="$timeout"
go test ./protocol -run=^$ -fuzz=FuzzReadFrame -fuzztime="$fuzztime" -parallel="$parallel" -timeout="$timeout"
go test ./protocol -run=^$ -fuzz=FuzzEnvelopeV2Open -fuzztime="$fuzztime" -parallel="$parallel" -timeout="$timeout"

echo "== knock fuzz (${fuzztime}) =="
go test ./knock -run=^$ -fuzz=FuzzOpenKnockFrame -fuzztime="$fuzztime" -parallel="$parallel" -timeout="$timeout"
go test ./knock -run=^$ -fuzz=FuzzSequenceTracker -fuzztime="$fuzztime" -parallel="$parallel" -timeout="$timeout"

echo "== auth fuzz (${fuzztime}) =="
go test ./auth -run=^$ -fuzz=FuzzServerAuthMalformedInput -fuzztime="$fuzztime" -parallel="$parallel" -timeout="$timeout"
