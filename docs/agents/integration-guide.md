# LLM integration guide

## Decision table

| Need | Use |
| --- | --- |
| Go service directly protects a listener | root `NewListener` |
| Go client connects to protected service | root `Dialer` |
| Caller owns a `net.Conn` pipeline | `NewServer` / `Server.Auth` |
| Low-level one-off server auth | `ServerAuth` with a shared replay cache |
| HTTP or TLS server | `NewListener`, then wrap the accepted clean connection/listener with TLS or HTTP serving |
| gRPC server | `NewListener`, then pass it to `grpc.Server.Serve` |
| Unmodified upstream binary | `relay` / `cmd/knock-proxy` |
| No firewall permission but require knock before TCP auth | `gate.KnockAuthOnly` |
| Port hiding with firewall rules | `gate.KnockFirewallAuth` or `gate.KnockFirewallOnly` |
| Protocol compatibility work | `protocol` package |

## Boundary

libknock authenticates before application protocol bytes are exposed and returns a clean `net.Conn`. It does not own TLS, HTTP, gRPC, application config, or business authorization.
