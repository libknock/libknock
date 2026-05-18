#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ${LIBKNOCK_REAL_FIREWALL_TESTS:-} != 1 ]]; then echo "set LIBKNOCK_REAL_FIREWALL_TESTS=1 to run real iptables validation"; exit 0; fi
command -v iptables >/dev/null
LIBKNOCK_FIREWALL_BACKEND=iptables go test ./firewall ./gate
