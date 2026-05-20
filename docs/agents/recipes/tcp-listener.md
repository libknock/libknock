# tcp-listener recipe

## Applicable scenario

root `libknock.NewListener` around an existing `net.Listener`.

## Files to modify

- aliases.go, netx/listener.go, docs/getting-started.md, docs/api.md, examples/custom-binary-protocol/server/main.go
- Update docs/tests next to the changed API or example.

## Files not to modify

- protocol/, internal/, firewall/
- Do not create per-connection replay caches.
- Do not move application-specific config parsing into SDK core.

## Minimal shape

```text
`ln, _ := net.Listen("tcp", addr); protected, _ := libknock.NewListener(ln, cfg); for { c, _ := protected.Accept(); go serve(c) }`
```

## Common mistakes

- Creating a replay cache per connection.
- Importing `protocol/` or `internal/` for normal application integration.
- Claiming libknock replaces TLS, mTLS, SSH, WireGuard, or application authorization.
- Skipping docs/api.md, docs/api-surface.md, README.md, and COMPATIBILITY.md when API behavior changes.

## Validation commands

```sh
`go test ./netx ./auth && scripts/check-integration.sh`
scripts/check-integration.sh
```
