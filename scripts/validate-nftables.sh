#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ${LIBKNOCK_REAL_FIREWALL_TESTS:-} != 1 ]]; then echo "set LIBKNOCK_REAL_FIREWALL_TESTS=1 to run real nftables validation"; exit 0; fi
command -v nft >/dev/null
LIBKNOCK_FIREWALL_BACKEND=nftables go test ./firewall ./gate
