# Integration anti-patterns

## Per-connection replay cache

Wrong: create `NewMemoryReplayCache` inside every accept loop iteration.

Right: create one cache per logical server runtime, or let `NewListener` / `NewServer` own it.

Reason: replay protection must span connections within the replay window.

## Starting from protocol/

Wrong: application code imports `protocol/` and hand-writes frames.

Right: use root `Dialer`, `NewListener`, or `ServerAuth`.

Reason: wire-level packages are for compatibility and advanced protocol work.

## Unsafe knock parsing

Wrong: call `ParseKnockFrameUnsafe` in a UDP listener exposed to the network.

Right: call `OpenKnockFrame` with a shared replay cache or use the high-level knock listeners.

Reason: unsafe parsing intentionally skips replay protection.

## SDK reads application config

Wrong: add `RunServer(configPath)` to SDK core.

Right: parse config in `cmd/` or the embedding application, then pass typed configs to the SDK.

## Blocking authentication callbacks

Do not perform network I/O, database writes, or slow logging directly in `ServerConfig.OnAuthenticated`. The callback runs synchronously on the authentication path; blocking it reduces auth throughput and can stall worker goroutines.

Use a caller-owned bounded queue when post-auth processing may block:

```go
type AsyncEventSink struct { ch chan auth.PeerInfo }

func NewAsyncEventSink(n int, handle func(auth.PeerInfo)) *AsyncEventSink {
    s := &AsyncEventSink{ch: make(chan auth.PeerInfo, n)}
    go func() { for p := range s.ch { handle(p) } }()
    return s
}

func (s *AsyncEventSink) OnAuthenticated(_ net.Conn, peer auth.PeerInfo) {
    select {
    case s.ch <- peer:
    default:
        // Drop, count, or fail according to caller policy. Do not block auth.
    }
}
```

Do not move the SDK callback invocation into an implicit goroutine: that would hide ordering, panic, and goroutine-leak semantics from callers.
