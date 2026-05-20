# Validation matrix

Status legend:

- `unit tested`: covered by regular Go tests.
- `integration tested`: exercised by local loopback or repository integration tests.
- `dry-run tested`: command generation or behavior validated without mutating a real host firewall.
- `race tested`: covered by selected `go test -race` packages.
- `fuzz smoke`: has short fuzz targets or commands suitable for CI/manual smoke.
- `not validated on real host`: no repository evidence of end-to-end validation on a real target host/device.
- `planned validation`: repeatable commands or scripts exist, but no long-run/real-host evidence has been recorded for this release.

| Area | Unit | Integration | Dry-run | Race | Fuzz | Hardware status | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Root TCP auth SDK | unit tested | integration tested | n/a | race tested | fuzz smoke | not validated on real host for all network topologies | Listener wrapping, dialer auth, replay cache, server proof, v1/v2 protocol paths. |
| Envelope v2 protocol | unit tested | integration tested | n/a | race tested | fuzz smoke | n/a | Route hint, padding buckets, AAD binding, candidate limits. |
| UDP knock active listener | unit tested | integration tested | n/a | race tested | fuzz smoke | not validated on real host | Binary AEAD knock frames only; no JSON fallback. |
| UDP sequence knock | unit tested | integration tested | n/a | race tested | fuzz smoke | not validated on real host | Sequence tracker and replay behavior covered by tests. |
| Gate auth-only | unit tested | integration tested | n/a | race tested | n/a | not validated on real host for all deployments | Listener-owned lifecycle and replay-cache behavior. |
| Gate knock-auth-only | unit tested | integration tested | n/a | race tested | fuzz smoke | not validated on real host | Requires prior knock and session-bound TCP auth. |
| Gate knock-firewall modes | unit tested | integration tested | dry-run tested | race tested | fuzz smoke | not validated on real host | Real firewall mutation must be validated per host. |
| Relay gateway | unit tested | integration tested | dry-run tested | race tested | fuzz smoke | not validated on real host | Separate upstream listener with shared knock/session logic. |
| Linux nftables | unit tested | limited script validation | dry-run tested | n/a | n/a | not validated on real host | Validate with `scripts/validate-nftables.sh` on target hosts. |
| Linux iptables | unit tested | limited script validation | dry-run tested | n/a | n/a | not validated on real host | Validate with `scripts/validate-iptables.sh` on target hosts. |
| Linux ipset + iptables | unit tested | limited script validation | dry-run tested | n/a | n/a | not validated on real host | Validate with `scripts/validate-ipset-iptables.sh` on target hosts. |
| UDP passive capture | unit tested | limited local package coverage | dry-run tested | race tested | fuzz smoke | not validated on real host | Requires packet capture privileges and platform support. |
| Windows packet capture/firewall paths | partial unit coverage | no | no | no | no | not validated on real host | Requires dedicated Windows host validation. |
| macOS BPF/pcap paths | partial unit coverage | no | no | no | no | not validated on real host | Requires dedicated macOS host validation. |
| Policy limiter and ban list | unit tested | n/a | n/a | race tested | n/a | n/a | Limiter semantics remain distinct from generic TTL cache semantics. |
| Observability events | unit tested | integration tested | n/a | n/a | n/a | n/a | Event sinks receive metadata; secrets and sealed payloads are not emitted. |

## Interpreting the matrix

`unit tested`, `integration tested`, `dry-run tested`, and `race tested` are repository evidence levels. They are not substitutes for target-host validation of firewall rule order, kernel modules, packet-capture privileges, NAT behavior, container network namespaces, or Windows/macOS driver installation. Keep release notes conservative unless a validation record exists in the shape of `docs/validation-template.md`.

Recommended local code gate:

```sh
scripts/check.sh
scripts/release-check.sh
```

Optional smoke gates:

```sh
go test -run=^$ -bench=. ./auth ./protocol ./knock ./policy
go test ./protocol -run=^$ -fuzz=FuzzEnvelopeV2Open -fuzztime=30s
go test ./knock -run=^$ -fuzz=FuzzOpenKnockFrame -fuzztime=30s
go test ./auth -run=^$ -fuzz=FuzzServerAuthMalformedInput -fuzztime=30s
```

Planned longer pre-stable fuzz and benchmark runs:

```sh
FUZZTIME=10m scripts/fuzz-long.sh
BENCHTIME=3s BENCHCOUNT=3 scripts/benchmark.sh
```

Record benchmark output, Go version, OS/architecture, CPU model, and whether tests used `-mod=vendor`. Until those records exist for a release, treat long fuzz and performance numbers as `planned validation`, not completed release evidence.


Dependency model: publish a standard source archive for normal Go module users and a companion `with-vendor` archive for offline review, reproducible local audit, LLM-assisted integration, and restricted CI. The vendored archive must include `vendor/`, `vendor/modules.txt`, `go.work`, and `go.work.sum`.
