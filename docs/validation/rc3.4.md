# v0.1.0-rc3.4 validation record

rc3.4 is a security and lifecycle hardening release candidate. It fixes audited concurrency, cancellation, relay-error reporting, envelope budget, replay-cache, firewall/configuration, bounded-state, and release-metadata defects. It does not add real-host validation claims.

## Local release gate run

- `scripts/check.sh`
- `scripts/check-integration.sh`
- `scripts/check-api.sh`
- `scripts/release-check.sh`
- `go test -race ./relay`
- `scripts/package-release.sh --with-vendor v0.1.0-rc3.4 <dist>`
- `sha256sum -c <dist>/*.sha256`

The gate covers non-vendor formatting, main-module tests, vet, selected race tests, nested modules, examples, short fuzz smoke, benchmark smoke, API snapshot, documentation links, duplicate scan, dependency/license smoke, and a vendored release-tree test.

## Environment-limited validation

| Area | Status | Reason | Follow-up |
| --- | --- | --- | --- |
| nftables real-host mutation | not validated | no controlled privileged host in this release run | run `scripts/validate-nftables.sh` on a controlled Linux host |
| iptables / ipset-iptables real-host mutation | not validated | no controlled privileged host in this release run | run the corresponding validation scripts and cleanup drill |
| UDP passive DROP behavior | not validated | requires target packet path and privileges | run `scripts/validate-udp-passive.sh` |
| TCP SYN / SYN-sequence path | not validated | raw packet/capture path is platform-specific | validate on the intended deployment host |
| Windows / macOS packet drivers | not validated | target driver environments unavailable | validate on supported target hosts |
| long fuzz campaigns | not part of RC local gate | short fuzz smoke only | run `FUZZTIME=10m scripts/fuzz-long.sh` before stable release |
| production throughput | not validated | benchmark smoke is not a workload baseline | record target-hardware benchmark evidence |
