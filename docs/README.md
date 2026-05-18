# libknock documentation

This directory contains detailed documentation for embedding, operating, testing, and extending `libknock`.

## Guides

- [Getting started](getting-started.md): first server/client integration, config mapping, and TLS/HTTP/gRPC composition.
- [Use cases](use-cases.md): typical integration scenarios for management endpoints, agents, RPC, custom TCP services, and relay gateways.
- [API reference](api.md): public types, functions, config structs, and extension interfaces.
- [Protocols](protocols.md): TCP auth protocol v1, TCP auth protocol v2, UDP knock frame, sessions, and server proof.
- [Gate and relay](gate-and-relay.md): listener gate modes and relay gateway composition.
- [Knock methods](knock-methods.md): supported knock methods, platform notes, and method selection.
- [Firewall backends](firewall.md): backend model, port binding, cleanup, and backend selection.
- [Observability](observability.md): event sinks, Prometheus adapter, and label/cardinality guidance.
- [Production deployment](production.md): operational defaults, backend selection, lifecycle, and platform notes.
- [Troubleshooting](troubleshooting.md): common integration and deployment failures.
- [Release checklist](release-checklist.md): repeatable checks before RC and stable releases.
- [Roadmap](roadmap.md): future validation and engineering work.
- [Maintenance notes](maintenance.md): internal reuse and duplication boundaries.
- [Validation template](validation-template.md): template for real host validation evidence.
- [License and notices](license.md): release license review guidance.
- [CI](ci.md): workflow and local release gates.
- [Doctor](doctor.md): compatibility command diagnostics and exit behavior.
- [Security model](security.md): trust boundaries, failure handling, and state windows.
- [Firewall deployment](deployment-firewall.md): backend choice and fallback risks.
- [Platform support](platform-support.md): stable, experimental, compile-only, and unsupported platform paths.
- [Validation matrix](validation-matrix.md): unit/integration/dry-run/hardware status by area.
- [Known limitations](known-limitations.md): validation boundaries and not-hardware-validated areas.
- [Development guide](development.md): repository layout, test matrix, release checks, and extension rules.

## Design summary

`libknock` works at the TCP connection boundary. The SDK authenticates its own binary frame and returns a clean `net.Conn` to the caller. The embedding application remains responsible for configuration, lifecycle, protocol handlers, TLS setup, logging policy, deployment, and business authorization.

The core API is intentionally small:

```go
ln = libknock.WrapListener(ln, serverConfig)
server, err := libknock.NewServer(serverConfig)
conn, peer, err := server.Auth(ctx, conn)
conn, peer, err := libknock.ServerAuth(ctx, conn, serverConfig)
err = libknock.ClientAuth(ctx, conn, clientConfig)
conn, err = (&libknock.Dialer{Base: baseDialer, Config: clientConfig}).DialContext(ctx, network, address)
```

Use `WrapListener` or `NewServer` for normal server integrations. Use `ServerAuth` directly only when the embedding application already owns connection acceptance and replay-cache lifetime.

## Recommended reading order

For application integration, read:

1. [Getting started](getting-started.md)
2. [API reference](api.md)
3. [Production deployment](production.md)

For gateway-style deployments, read:

1. [Gate and relay](gate-and-relay.md)
2. [Knock methods](knock-methods.md)
3. [Firewall backends](firewall.md)

For release or contribution work, read:

1. [Protocols](protocols.md)
2. [Release checklist](release-checklist.md)
3. [Development guide](development.md)
