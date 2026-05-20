# grpc-client recipe

## Applicable scenario

gRPC clients that need libknock before HTTP/2 starts.

## Files to modify

- examples/grpc-client/main.go, test/integration/grpc/examples/grpc-client/main.go, netx/dialer.go
- Update docs/tests next to the changed API or example.

## Files not to modify

- protocol/, internal/
- Do not create per-connection replay caches.
- Do not move application-specific config parsing into SDK core.

## Minimal shape

```text
use `libknock.Dialer(cfg)` or a context dialer that calls `libknock.ClientAuth` before returning the conn
```

## Common mistakes

- Creating a replay cache per connection.
- Importing `protocol/` or `internal/` for normal application integration.
- Claiming libknock replaces TLS, mTLS, SSH, WireGuard, or application authorization.
- Skipping docs/api.md, docs/api-surface.md, README.md, and COMPATIBILITY.md when API behavior changes.

## Validation commands

```sh
`go test ./test/integration/grpc/... && go build ./examples/grpc-client`
scripts/check-integration.sh
```
