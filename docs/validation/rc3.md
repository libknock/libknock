# v0.1.0-rc3 validation record

## Ran for this release candidate

- `go test ./...`
- `go vet ./...`
- `go test -race ./auth ./firewall ./gate ./knock ./netx ./policy ./protocol ./relay`
- `go -C observability/prometheus test ./...`
- `go -C observability/prometheus vet ./...`
- `scripts/check-api.sh`
- `scripts/release-check.sh`
- `scripts/package-release.sh --with-vendor v0.1.0-rc3 <dist>`
- archive path and SHA-256 audits

## Not run / reason / risk / follow-up

| Area | Status | Reason | Risk | Follow-up |
| --- | --- | --- | --- | --- |
| nftables real-host mutation | not validated | no privileged target host in this release environment | rule ordering, cleanup, and timeout behavior may differ by host | run `scripts/validate-nftables.sh` on a controlled Linux host |
| iptables real-host mutation | not validated | no privileged target host in this release environment | process-managed cleanup may leave temporary ACCEPT rules after abnormal exit | run `scripts/validate-iptables.sh` and cleanup drills |
| ipset-iptables real-host mutation | not validated | no privileged target host in this release environment | ipset/kernel module availability and IPv6 handling need host proof | run `scripts/validate-ipset-iptables.sh` |
| UDP passive DROP behavior | not validated | packet capture privileges and DROP rules require host-level setup | scan behavior is deployment-specific | validate `udp-passive` and `udp-passive-seq` with `DropUDPKnockPort` |
| Windows WinDivert/Npcap | compile-only / not validated | no Windows host attached | driver install and capture semantics unproven | run Windows packet-path checklist before stable |
| macOS BPF/pcap | compile-only / not validated | no macOS host attached | capture device permissions and BPF behavior unproven | run macOS packet-path checklist before stable |
| long fuzz | not run | RC smoke only | rare parser/protocol bugs may remain | run `FUZZTIME=10m scripts/fuzz-long.sh` before stable |
| production throughput | not validated | no fixed production-like host profile | benchmark data is only microbenchmark guidance | collect benchstat on target hardware |
