# v0.1.0-rc3.2 validation record

rc3.2 is scoped as CI recovery, release-process hardening, observability/config-guard improvements, and documentation/agent scaffolding. It does not claim additional target-host validation beyond the existing rc3/rc3.1 evidence unless commands are recorded below.

## Local release gate run

Run from the repository/workspace root with `go.work` enabled. Do not combine `GOWORK=off` with workspace vendor mode.

Passed for this RC:

- `go test -mod=vendor ./...`
- `go vet -mod=vendor ./...`
- `go build -mod=vendor ./...`
- `go test -race -mod=vendor ./auth ./firewall ./gate ./knock ./netx ./policy ./protocol ./relay ./internal/cache ./internal/gatewaycore`
- `go test -mod=vendor ./observability/prometheus/...`
- `go test -mod=vendor ./test/integration/grpc/...`
- `go test -mod=vendor ./examples/grpc-client/... ./examples/grpc-server/...`
- `scripts/check-api.sh`
- `python3 scripts/check-doc-links.py`
- `STRICT=1 scripts/check-duplication.sh .`
- `scripts/check.sh`
- `scripts/release-check.sh`
- `scripts/package-release.sh --with-vendor v0.1.0-rc3.2 /tmp/libknock-rc32-release`
- `sha256sum -c /tmp/libknock-rc32-release/*.sha256`
- archive audit: standard zip excludes `vendor/`; with-vendor zip includes `vendor/modules.txt`

## Platform-specific validation matrix

| Area | Status | Evidence type | Follow-up |
| --- | --- | --- | --- |
| core SDK/auth/protocol/cache/netx/relay | unit/integration gate required | `go test -mod=vendor ./...` plus race subset | keep green for every RC |
| Prometheus adapter | nested-module gate required | `go test -mod=vendor ./observability/prometheus/...` | keep labels bounded |
| gRPC examples/integration | nested-module gate required | `go test -mod=vendor ./test/integration/grpc/...` and examples | keep replacement path documented |
| nftables real-host mutation | requires privileged Linux host validation | not validated on current host unless command output is appended | run `scripts/validate-nftables.sh` |
| iptables real-host mutation | requires privileged Linux host validation | not validated on current host unless command output is appended | run `scripts/validate-iptables.sh` and cleanup drills |
| ipset-iptables real-host mutation | requires privileged Linux host validation | not validated on current host unless command output is appended | run `scripts/validate-ipset-iptables.sh` |
| UDP passive DROP behavior | requires privileged packet/firewall host validation | not validated on current host unless command output is appended | validate `udp-passive` and `udp-passive-seq` with `DropUDPKnockPort` |
| Windows WinDivert/Npcap | compile-only / experimental | no Windows host evidence in this RC | run packet-driver checklist before stable |
| macOS BPF/pcap | compile-only / experimental | no macOS host evidence in this RC | run BPF/pcap checklist before stable |
| long fuzz | not part of standard RC gate | short fuzz smoke lives in release-check | run `FUZZTIME=10m scripts/fuzz-long.sh` before stable |
| production throughput | not validated | microbench smoke only | collect benchstat on target hardware |

## Release claim boundary

If rc3.2 is published without additional host validation, describe it as CI/release-process, code-quality, observability, and documentation hardening. Do not claim real-host firewall mutation, passive UDP DROP behavior, TCP SYN packet paths, Windows packet drivers, macOS BPF/pcap, long fuzz, or production throughput validation.
