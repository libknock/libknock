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


## Task index

| Task | Read | Validate |
| --- | --- | --- |
| Protect a Go TCP service | `recipes/tcp-listener.md`, `../getting-started.md` | `go test ./netx ./auth` |
| Add TLS/HTTP after admission | `recipes/tls-http-server.md` | `go build ./examples/tls-server ./examples/tls-client ./examples/http-client/server ./examples/http-client/client` |
| Add gRPC integration | `recipes/grpc-server.md`, `recipes/grpc-client.md` | `go -C test/integration/grpc test ./...` |
| Protect an unmodified binary | `recipes/relay-gateway.md`, `../gate-and-relay.md` | `go test ./relay ./cmd/knock-proxy` |
| Require knock before TCP auth without firewall | `recipes/knock-auth-only.md`, `../modes.md` | `go test ./gate ./relay ./knock ./auth` |
| Use host firewall admission | `recipes/firewall-gate.md`, `../firewall.md`, `../validation-template.md` | package tests plus target-host validation |
| Map product config to SDK structs | `recipes/config-mapping.md`, `../api-surface.md` | tests for the product config layer plus SDK package tests |

Prefer `bash scripts/check-integration.sh` when execute bits are unavailable in an unpacked archive.
