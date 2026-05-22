# Add a netx backpressure test

## Modify

- `netx/listener.go`
- `netx/listener_test.go`
- `netx/events.go` if event surface changes
- `observability/events.go` and `observability/prometheus/*` if metrics change
- `docs/observability.md` for operator semantics

## Do not modify

- Auth protocol parsing or replay-cache behavior.
- Metric labels with unbounded remote/user input.

## Required commands

```sh
go test -mod=vendor ./netx ./observability/...
go test -race -mod=vendor ./netx
```

## Completion report

State queue capacity, worker count, expected drop/error event, metric labels, and exact commands run.
