# Add a replay cache test

## Modify

- `auth/replay.go`
- `auth/replay_test.go`
- `internal/cache/ttl_lru.go` and tests if shared TTL/LRU behavior changes
- `docs/observability.md` if capacity or metric semantics change

## Do not modify

- Authentication wire format or client/server frame layout.
- Per-connection replay cache wiring; replay state must remain shared for a logical server runtime.

## Required commands

```sh
go test -mod=vendor ./auth ./internal/cache
go test -race -mod=vendor ./auth ./internal/cache
```

## Completion report

State the cache invariant being protected, expected fail-open/fail-closed behavior, active vs stored length semantics, and exact commands run.
