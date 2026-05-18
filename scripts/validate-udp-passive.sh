#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ${LIBKNOCK_REAL_FIREWALL_TESTS:-} != 1 ]]; then echo "set LIBKNOCK_REAL_FIREWALL_TESTS=1 to run real udp-passive validation"; exit 0; fi
go test ./knock -run 'UDPPassive|Passive'
