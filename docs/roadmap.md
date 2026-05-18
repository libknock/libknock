# Roadmap

This roadmap tracks real engineering debt and validation work. It is not a promise that every item will ship in the next release.

## Validation

- Run full Linux nftables, iptables, and ipset-iptables validation on representative hosts.
- Validate Windows TCP SYN paths with WinDivert and Npcap installed.
- Validate macOS raw/BPF/pcap paths on supported macOS versions.
- Add longer fuzz runs for protocol frame parsing, Envelope v2 opening, UDP knock frames, sequence aggregation, and malformed TCP auth streams.

## SDK and runtime

- Keep the root package focused on the small TCP auth SDK surface.
- Continue moving shared gate/relay runtime mechanics into internal packages without expanding public API.
- Expand examples only where they demonstrate distinct integration patterns.

## Operations

- Keep validation matrix entries honest: unit/dry-run/integration coverage should not be presented as hardware validation.
- Extend CI with safe smoke gates where runtime and time budget allow.
