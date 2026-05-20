#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
benchtime=${BENCHTIME:-3s}
count=${BENCHCOUNT:-3}

packages=(./protocol ./knock ./auth ./gate)
patterns=(
  'BenchmarkProtocolFrameEncodeDecode|BenchmarkEnvelopeV2SealOpen|BenchmarkEnvelopeV2OpenWithRouteHint|BenchmarkEnvelopeV2OpenWithHintNoneManyCandidates'
  'BenchmarkKnockFrameBuildOpen|BenchmarkSequenceTracker'
  'BenchmarkReplayCacheCheckAndMark'
  'BenchmarkGateAuthOnlyAccept'
)
for i in "${!packages[@]}"; do
  go test -run=^$ -bench="${patterns[$i]}" -benchmem -benchtime="$benchtime" -count="$count" "${packages[$i]}"
done
