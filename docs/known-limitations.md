# Known limitations

This page records the current engineering boundaries of libknock. It is intentionally conservative: unit tests, dry-run scripts, and local integration tests are not presented as full hardware or production validation.

## Validation environment

Current automated validation covers Go unit tests, selected race tests, fuzz targets, protocol compatibility tests, dry-run firewall command checks, and local loopback integration paths. It does not prove behavior on every host firewall, packet capture driver, kernel version, NAT topology, or production network.


## Centralized not-validated list

The following areas are intentionally tracked as `not validated on real host` for this release round unless a completed `docs/validation-template.md` record says otherwise:

- Linux `nftables`, `ipset-iptables`, and `iptables` fallback rule creation, revoke, cleanup, repeated startup cleanup, and abnormal-exit stale-rule recovery.
- Linux firewall IPv4/IPv6 behavior across host distributions, containers, namespaces, NAT, and existing firewall policy order.
- UDP passive capture with `drop_udp_knock_port`, including root/CAP_NET_RAW/pcap/BPF privileges and firewall DROP interaction.
- TCP SYN and TCP SYN sequence raw-packet send/listen paths.
- Windows WinDivert/Npcap and macOS BPF/pcap runtime behavior.
- Long-running fuzz campaigns and production performance baselines.

Repository unit tests, mock runner tests, dry-run scripts, build checks, and short fuzz/benchmark smoke are useful code-level evidence, but they are not real-host validation.

## Platform firewall backends

- Linux nftables, iptables, and ipset command generation is covered by tests and validation scripts, but still needs host-level validation on real distributions and firewall configurations.
- Windows support depends on the intended backend and host privileges. WinDivert/Npcap-style packet handling is platform-specific and not validated on real host in this repository.
- macOS passive capture paths depend on BPF/pcap privileges and host networking behavior. They are not validated on real host here.
- Firewall cleanup is designed to be idempotent, but operators should still run staged validation on the target host before exposing a service.

## Knock methods

UDP knock uses binary AEAD frames. There is no JSON fallback. Active UDP and UDP sequence listeners have unit and loopback coverage; passive capture and raw SYN methods require platform privileges and driver support and are therefore marked platform-specific until tested on the target host.

`gate` currently requires synchronous listener readiness for its supported knock listener path. Methods that cannot provide that readiness are rejected by the gate API rather than pretending the service is protected before the knock listener is actually bound.

## Session binding

Knock + TCP auth modes bind TCP authentication to a prior knock session. Session IDs, client IDs, remote addresses, and protected ports are part of the intended security boundary. Disabling session binding or using firewall-only admission weakens attribution and should be treated as an explicit deployment trade-off.

## Failure semantics

Authentication failures intentionally do not expose detailed reasons to unauthenticated network peers; callers and event sinks can inspect internal errors. Firewall-backed gates fail closed when they cannot record or enforce a lease. Cleanup and revoke errors are observable and should be handled as operational incidents, but a best-effort cleanup attempt is still made on shutdown.

## Operational scope

libknock authenticates before the application protocol starts and then returns a clean `net.Conn`. It does not inspect application payloads, replace TLS, manage long-term secret storage, or guarantee firewall behavior outside the configured backend and host environment.

## Fuzzing and performance

Short fuzz smoke runs and benchmarks are useful regression gates. Long-duration fuzzing and platform-specific performance characterization remain release engineering tasks and should be recorded separately when completed.

## Validation levels

Validation status is tracked by capability level:

- stable: covered by ordinary CI unit/integration tests.
- platform-specific: depends on Linux firewall/raw socket capabilities and should be validated on the target platform.
- experimental: API or behavior can still change.
- not fully validated: documented behavior exists but has not been exercised in this release round on real machines.

This release round does not claim full-machine validation for every firewall backend, Windows path, or macOS passive capture path.

## RC3.2 documentation-pass boundary

rc3.2 documentation scaffolding does not reduce the known validation limits above. In particular, a generated `with-vendor` archive and IDE-assistant guidance improve reviewability, but they are not evidence of real-host firewall behavior, packet-capture driver behavior, long fuzz coverage, or production throughput.
