# Observability

`libknock` reports authentication, knock, firewall, and relay activity through event interfaces. Applications choose how those events are logged, counted, exported, or sampled.

## Authentication events

```go
type EventSink interface {
    OnAccept(remote net.Addr)
    OnAuthOK(peer PeerInfo)
    OnAuthFail(remote net.Addr, reason error)
    OnReplay(remote net.Addr, peerHint uint64)
    OnReplayCacheFull(remote net.Addr, peerHint uint64, length, capacity int)
    OnRateLimited(remote net.Addr)
}
```

Attach it to `ServerConfig.Events`.

```go
serverCfg.Events = myEventSink
```

## Gateway events

`gate` and `relay` use gateway-level event types from the `observability` package:

- knock accepted
- knock failed
- firewall allow
- firewall error
- relay connection opened
- relay connection closed
- relay error

Attach the sink through `GateConfig.Events` or `relay.Gateway.Events`.

## Prometheus adapter


Relay duration histogram buckets are startup configuration, not public input. If `RelayDurationBuckets` is set, buckets must be positive and strictly increasing. `prometheus.New` returns an error for invalid bucket configuration or registration conflicts; `prometheus.MustNew` intentionally panics for the same local startup bugs so services can fail fast before serving traffic.

The Prometheus adapter lives in a nested module:

```go
import knockprom "github.com/libknock/libknock/observability/prometheus"
```

Example:

```go
reg := prometheus.NewRegistry()

sink, err := knockprom.New(knockprom.Config{
    Registerer: reg,
})
if err != nil {
    return err
}

serverCfg.Events = sink
gateway.Events = sink
```

Test it separately:

```sh
go -C observability/prometheus test ./...
```

## Label guidance

The adapter keeps client labels disabled by default. Enable `IncludeClientLabel` only when client cardinality is controlled.

For method labels, use the package method names:

```text
tcp-syn
tcp-syn-seq
udp
udp-seq
udp-passive
udp-passive-seq
tcp-auth
unknown
```

If an application accepts user-controlled method values, normalize unknown values to `unknown` before exporting them as labels.

## Logging guidance

A production event sink should avoid logging raw secrets, full frame bytes, or sealed payload bytes. Log stable operational fields instead:

- remote address
- client ID after successful authentication
- method
- protocol
- protected port
- reason class
- duration
- result

Recommended failure log shape:

```json
{
  "component": "libknock",
  "event": "auth_fail",
  "remote": "203.0.113.10:49152",
  "reason": "auth_failed",
  "protocol": "tcp-auth-envelope-v2"
}
```

Recommended success log shape:

```json
{
  "component": "libknock",
  "event": "auth_ok",
  "client_id": "client-001",
  "remote": "203.0.113.10:49152",
  "method": "tcp-auth",
  "server_port": 9000,
  "protocol": "tcp-auth-envelope-v2"
}
```

## Metrics guidance

Track at least:

- accepted TCP connections before auth
- successful authentication count
- failed authentication count by reason class
- replay count
- replay cache capacity and full-cache rejection count
- rate-limited count
- knock accepted count
- knock failed count by reason class
- firewall allow errors
- relay upstream errors
- relay pending-queue full/drop counters
- current relay connections

Keep high-cardinality labels disabled unless your deployment has strict bounds.

## Label normalization and sensitive fields

The Prometheus adapter normalizes method labels to the known method set and reports unknown method values as `unknown`. Failure reasons are exported as bounded reason classes rather than raw error strings. Client labels are disabled by default because client IDs can be high-cardinality; enable `IncludeClientLabel` only when the deployment has a bounded client set.

Event payloads and metric labels must not include secrets, sealed payload bytes, raw frames, AEAD nonces beyond existing operational hints, or full unbounded error text. Prefer stable enums for `method`, `mode`, `reason`, and `stage`; map unrecognized values to `unknown` or a small bounded class.

## Cache and capacity metrics

`TTLLRU.Len()` is a stored-entry upper bound. It can include expired entries until a read path or `Sweep` removes them, so dashboards should not treat it as an exact active-entry count. For pressure signals, prefer sweep-aware active counts where available and record replay-cache-full or limiter-full decisions separately. The Prometheus adapter exports `libknock_auth_replay_cache_full_total`, `libknock_auth_replay_cache_len`, and `libknock_auth_replay_cache_capacity` when the auth path reports `ErrReplayCacheFull`; treat that as either abusive fake-nonce traffic or an undersized cache.

Relay pending-queue pressure is reported through `RelayErrorEvent{Stage:"pending_full", DroppedCount, Pending}` and exported as `libknock_relay_pending_full_total`, `libknock_relay_dropped_total`, and `libknock_relay_pending_current`. Spikes usually mean a burst; sustained growth means the auth worker count, upstream latency, or caller-side rate limits need attention.

Security-sensitive stores fail closed at capacity: replay caches reject new nonces rather than evicting active nonces, and rate limiters reject new keys rather than evicting active buckets. These events should be observable as capacity, abuse, or configuration signals, not as successful admissions.
