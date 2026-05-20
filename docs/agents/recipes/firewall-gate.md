# firewall-gate recipe

## Applicable scenario

firewall-backed admission where libknock opens temporary host rules.

## Files to modify

- gate/, firewall/, internal/gatewaycore/, docs/firewall.md, docs/gate-and-relay.md
- Update docs/tests next to the changed API or example.

## Files not to modify

- protocol/, auth/ wire code
- Do not create per-connection replay caches.
- Do not move application-specific config parsing into SDK core.

## Minimal shape

```text
use `gate.New`/`Gate` with a validated firewall backend and TTL; fail closed if lease recording fails
```

## Common mistakes

- Creating a replay cache per connection.
- Importing `protocol/` or `internal/` for normal application integration.
- Claiming libknock replaces TLS, mTLS, SSH, WireGuard, or application authorization.
- Skipping docs/api.md, docs/api-surface.md, README.md, and COMPATIBILITY.md when API behavior changes.

## Validation commands

```sh
go test ./gate ./firewall ./relay
bash scripts/check-integration.sh
```
