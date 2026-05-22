# Add an auth error test

## Modify

- `auth/errors.go`
- `auth/server.go`
- `auth/server_test.go`
- `observability/prometheus/sink.go` and `sink_test.go` if the error is observable
- Docs that describe public failure semantics, usually `docs/observability.md` or `docs/protocols.md`

## Do not modify

- Protocol wire format files unless the task explicitly changes bytes on the wire.
- SDK root aliases without updating `docs/api-surface.md` and compatibility notes.

## Required commands

```sh
go test -mod=vendor ./auth ./observability/...
scripts/check-doc-links.py
```

## Completion report

List the sentinel error, whether it is public or internal-only, how `publicError` maps it, metric label behavior, and exact commands run.
