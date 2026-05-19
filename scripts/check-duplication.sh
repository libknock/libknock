#!/usr/bin/env bash
set -euo pipefail

root=${1:-.}
status=0

check_single() {
  local pattern=$1
  local label=$2
  local count
  count=$( (grep -R "$pattern" "$root" --include='*.go' --exclude-dir=.git --exclude-dir=vendor 2>/dev/null || true) | wc -l | tr -d ' ' )
  if [ "$count" -gt 1 ]; then
    echo "duplicate $label: $count matches" >&2
    grep -R "$pattern" "$root" --include='*.go' --exclude-dir=.git --exclude-dir=vendor >&2 || true
    status=1
  fi
}

check_single 'func ShouldManualRevoke' ShouldManualRevoke
check_single 'func FirewallOpContext' FirewallOpContext
check_single 'func ValidateDropUDPKnockPort' ValidateDropUDPKnockPort
check_single 'func DefaultString' DefaultString
check_single 'func UDPListenForKnockPort' UDPListenForKnockPort
check_single 'func UDPListenStringForKnockPort' UDPListenStringForKnockPort
check_single 'func acceptsProtocol' acceptsProtocol
check_single 'func acceptsAuthProtocol' acceptsAuthProtocol

if command -v dupl >/dev/null 2>&1; then
  dupl -threshold 80 -vendor=false "$root" || status=$?
else
  if [ "${STRICT:-0}" = "1" ]; then
    echo "error: dupl not found; install with: go install github.com/mibk/dupl@latest" >&2
    status=1
  else
    echo "warning: dupl not found; install with: go install github.com/mibk/dupl@latest" >&2
  fi
fi

if [ "$status" -ne 0 ]; then
  if [ "${STRICT:-0}" = "1" ]; then
    echo "duplication scan failed" >&2
    exit "$status"
  fi
  echo "warning: duplication scan reported matches; review whether shared code belongs in internal packages" >&2
fi
exit 0
