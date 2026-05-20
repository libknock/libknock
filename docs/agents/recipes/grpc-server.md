# grpc-server recipe

## Applicable scenario

gRPC servers that own their listener.

## Files to modify

- examples/grpc-server/main.go, test/integration/grpc/examples/grpc-server/main.go, docs/agents/integration-guide.md
- Update docs/tests next to the changed API or example.

## Files not to modify

- protocol/, internal/
- Do not create per-connection replay caches.
- Do not move application-specific config parsing into SDK core.

## Minimal shape

```text
create `net.Listener`, wrap with `libknock.NewListener`, then call `grpcServer.Serve(protected)`
```

## Common mistakes

- Creating a replay cache per connection.
- Importing `protocol/` or `internal/` for normal application integration.
- Claiming libknock replaces TLS, mTLS, SSH, WireGuard, or application authorization.
- Skipping docs/api.md, docs/api-surface.md, README.md, and COMPATIBILITY.md when API behavior changes.

## Validation commands

```sh
`go test ./test/integration/grpc/... && go build ./examples/grpc-server`
scripts/check-integration.sh
```
