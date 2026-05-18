# Platform support

Status values:

- `stable`: supported by the core SDK and covered by routine tests.
- `experimental`: implementation exists, but deployment depends on platform privileges, packet capture drivers, or additional validation.
- `compile-only`: source is expected to build for the platform, but repository automation does not prove runtime behavior.
- `not supported`: no supported runtime path in this repository.

| Platform | Auth-only TCP SDK | Relay | UDP knock | UDP passive | TCP SYN knock | TCP SYN sequence | Firewall backend |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | stable | stable | stable | experimental | experimental | experimental | experimental: nftables, ipset-iptables, iptables; manual validation required |
| Windows | stable | stable | stable | compile-only / driver-dependent | compile-only / WinDivert or Npcap required | compile-only / WinDivert or Npcap required | not supported by built-in firewall backends |
| macOS | stable | stable | stable | compile-only / BPF or pcap required | compile-only / BPF or pcap required | compile-only / BPF or pcap required | not supported by built-in firewall backends |

`stable` here means the library path is stable, not that every host topology has been hardware validated. See [Validation matrix](validation-matrix.md), [Known limitations](known-limitations.md), and [Validation template](validation-template.md) before claiming a deployment is verified.
