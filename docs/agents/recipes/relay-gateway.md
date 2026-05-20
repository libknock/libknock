# relay-gateway recipe

## Applicable scenario

unmodified upstream binaries protected by a local relay.

## Files to modify

- relay/, cmd/knock-proxy/, docs/gate-and-relay.md, docs/modes.md
- Update docs/tests next to the changed API or example.

## Files not to modify

- root SDK API surface unless adding embedding API
- Do not create per-connection replay caches.
- Do not move application-specific config parsing into SDK core.

## Minimal shape

```text
configure `Gateway{Listen, Upstream, Auth, Firewall, KnockMethod}` or `knock-proxy` YAML
```

## Common mistakes

- Creating a replay cache per connection.
- Importing `protocol/` or `internal/` for normal application integration.
- Claiming libknock replaces TLS, mTLS, SSH, WireGuard, or application authorization.
- Skipping docs/api.md, docs/api-surface.md, README.md, and COMPATIBILITY.md when API behavior changes.

## Validation commands

```sh
`go test ./relay ./cmd/knock-proxy`
scripts/check-integration.sh
```
