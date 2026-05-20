# config-mapping recipe

## Applicable scenario

mapping operator config files into SDK structs outside SDK core.

## Files to modify

- cmd/knock-proxy/config.go, docs/configuration.md, docs/api-surface.md
- Update docs/tests next to the changed API or example.

## Files not to modify

- SDK core packages for app-specific YAML/TOML parsing
- Do not create per-connection replay caches.
- Do not move application-specific config parsing into SDK core.

## Minimal shape

```text
parse config in your binary, then populate `auth.ServerConfig`, `netx.ListenerConfig`, `relay.Gateway`, or `gate.Config`
```

## Common mistakes

- Creating a replay cache per connection.
- Importing `protocol/` or `internal/` for normal application integration.
- Claiming libknock replaces TLS, mTLS, SSH, WireGuard, or application authorization.
- Skipping docs/api.md, docs/api-surface.md, README.md, and COMPATIBILITY.md when API behavior changes.

## Validation commands

```sh
`go test ./cmd/knock-proxy ./auth ./netx`
scripts/check-integration.sh
```
