# Release notes

## Unreleased

- Root package API is intentionally narrowed to the common TCP auth SDK entry points. Advanced auth protocol selectors, gate modes, relay configuration, firewall backends, knock methods, and observability hooks are accessed through subpackages.
- Gate listener lifecycle now owns associated gate resources, and close paths are idempotent.
- Gate UDP knock listeners bind synchronously before returning the protected TCP listener.
- Shared internal helpers now cover binary codec, cryptographic primitives, timer lifecycle, and gate/relay runtime mechanics.
- Validation documentation now distinguishes unit, dry-run, integration, race, fuzz-smoke, and not-hardware-validated states.
- Firewall backend command behavior has dry-run/fake-runner tests, but real nftables/iptables/ipset host validation remains a release task.
- Windows WinDivert/Npcap and macOS BPF/pcap paths remain platform-specific and not fully hardware validated by repository automation.
