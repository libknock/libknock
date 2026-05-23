# Platform support

Status values:

- `stable`: supported by the core SDK and covered by routine tests.
- `experimental`: implementation exists, but deployment depends on platform privileges, packet capture drivers, or additional validation.
- `compile-only`: source is expected to build for the platform, but repository automation does not prove runtime behavior.
- `not supported`: no supported runtime path in this repository.

| Platform | Auth-only TCP SDK | Relay | UDP knock | UDP passive | TCP SYN knock | TCP SYN sequence | Firewall backend |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | stable | stable | stable | experimental | experimental | experimental | experimental: nftables, ipset-iptables, iptables; not validated on real host |
| Windows | stable | stable | stable | compile-only / driver-dependent | compile-only / WinDivert or Npcap required | compile-only / WinDivert or Npcap required | not supported by built-in firewall backends |
| macOS | stable | stable | stable | compile-only / BPF or pcap required | compile-only / BPF or pcap required | compile-only / BPF or pcap required | not supported by built-in firewall backends |

`stable` here means the library/API path is stable, not that every host topology has been validated on a real host. See [Validation matrix](validation-matrix.md), [Known limitations](known-limitations.md), and [Validation template](validation-template.md) before claiming a deployment is verified.


Evidence levels are documented separately in the validation matrix. Treat active UDP as the cross-platform baseline; TCP SYN, passive capture, Linux firewall mutation, Windows driver paths, and macOS BPF/pcap paths are platform-specific until validated on the target host.

## RC3.3 note

rc3.3 does not change platform support. It hardens timer/shutdown firewall revoke lifecycle behavior and documents lease renewal semantics, but it adds no new target-host firewall or packet-driver evidence. Continue to treat Linux firewall mutation, passive UDP capture, TCP SYN methods, Windows packet drivers, and macOS BPF/pcap as target-host validation items.

## RC3.2 note

rc3.2 does not change platform support. It is a documentation and release-scaffolding pass unless a later validation record explicitly adds host evidence. Continue to treat Linux firewall mutation, passive UDP capture, TCP SYN methods, Windows packet drivers, and macOS BPF/pcap as target-host validation items.
