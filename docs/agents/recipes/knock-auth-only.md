# knock-auth-only recipe

## Applicable scenario

deployments that require a knock session before TCP auth.

## Files to modify

- gate/, relay/, knock/, docs/modes.md, docs/gate-and-relay.md
- Update docs/tests next to the changed API or example.

## Files not to modify

- protocol/ wire code unless changing frame format
- Do not create per-connection replay caches.
- Do not move application-specific config parsing into SDK core.

## Minimal shape

```text
configure knock clients, shared replay cache, session binding, and TCP auth with matching `session_id`
```

## Common mistakes

- Creating a replay cache per connection.
- Importing `protocol/` or `internal/` for normal application integration.
- Claiming libknock replaces TLS, mTLS, SSH, WireGuard, or application authorization.
- Skipping docs/api.md, docs/api-surface.md, README.md, and COMPATIBILITY.md when API behavior changes.

## Validation commands

```sh
`go test ./gate ./relay ./knock ./auth`
scripts/check-integration.sh
```
