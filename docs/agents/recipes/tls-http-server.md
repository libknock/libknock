# tls-http-server recipe

## Applicable scenario

TLS/HTTP servers that should authenticate before TLS or HTTP bytes are read.

## Files to modify

- examples/tls-server/main.go, examples/tls-client/main.go, examples/http-client/server/main.go, examples/http-client/client/main.go, docs/getting-started.md
- Update docs/tests next to the changed API or example.

## Files not to modify

- protocol/, internal/
- Do not create per-connection replay caches.
- Do not move application-specific config parsing into SDK core.

## Minimal shape

```text
wrap the TCP listener with `libknock.NewListener`, then pass the protected listener to `tls.Server` or `http.Server.Serve`
```

## Common mistakes

- Creating a replay cache per connection.
- Importing `protocol/` or `internal/` for normal application integration.
- Claiming libknock replaces TLS, mTLS, SSH, WireGuard, or application authorization.
- Skipping docs/api.md, docs/api-surface.md, README.md, and COMPATIBILITY.md when API behavior changes.

## Validation commands

```sh
`go build ./examples/tls-server ./examples/tls-client ./examples/http-client/server ./examples/http-client/client`
scripts/check-integration.sh
```
