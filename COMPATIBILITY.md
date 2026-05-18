# Compatibility policy

`libknock` v0.1.0-rc1 is a pre-release. The project keeps the common TCP authentication SDK surface small and documents advanced packages separately so future wire-format and platform work does not accidentally freeze too much API.

## Stable for the v0.1.x release-candidate line

The root package is the preferred stable entry point for application integrations:

- `WrapListener`
- `NewServer`
- `ServerAuth`
- `ClientAuth`
- `Dialer`
- `ServerConfig`
- `ClientConfig`
- `PeerInfo`
- root aliases for stable constants and auth interfaces such as `MinSecretSize`, `SecretResolver`, `ReplayCache`, `EventSink`, `Policy`, and knock-session interfaces

The `auth` package is also intended for integrations that need explicit protocol selectors, custom resolvers, replay caches, policy hooks, or event sinks.

## Advanced / wire-level packages

The `protocol` package exposes low-level frame and envelope helpers for interoperability testing, custom transports, and diagnostics. It is not a promise that every exported wire-level helper remains unchanged across v0.1.x pre-releases. In particular, raw envelope/header/payload helpers may change if the release-candidate wire format requires correction.

## Platform and gateway packages

`gate`, `relay`, `firewall`, `knock`, and `observability` are public but advanced packages. They are usable in v0.1.0-rc1, but some paths are platform-specific and need host validation:

- raw packet and passive-capture knock methods;
- TCP SYN / SYN-sequence methods;
- Windows WinDivert / Npcap paths;
- macOS BPF / pcap paths;
- Linux nftables / iptables / ipset real firewall enforcement.

The repository automation covers unit, race, dry-run, localhost integration, fuzz-smoke, and cross-build checks. It does not claim full hardware/firewall validation for every target host.

## Command compatibility

`cmd/knock-proxy` is a relay compatibility entrypoint for simple proxy deployments. It is not the unified CLI for every SDK gate mode. Applications that need `auth-only`, `knock-auth-only`, `knock-firewall-auth`, or `knock-firewall-only` should embed the SDK packages directly or use purpose-built examples.
