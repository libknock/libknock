# Production deployment

This document summarizes production-oriented defaults, backend selection, lifecycle handling, and platform notes.

## Recommended defaults

| Setting | Recommended value |
| --- | --- |
| TCP auth protocol | `tcp-auth-envelope-v2` |
| `AuthTimeout` | `3s` |
| `TimeWindow` | `30s` |
| `ReplayCache` TTL | at least `TimeWindow * 2` |
| `MaxFrameSize` | `1024` unless the deployment needs a smaller bound |
| `MaxAuthAttempts` | default `64` |
| secret length | 32 random bytes recommended; 16 bytes minimum |
| envelope v2 hint mode | `route-hint` |
| envelope v2 padding | `random-bucket` |
| server proof | disabled unless specifically required |

## Secret handling

Use random secrets and keep them out of logs.

```sh
openssl rand -base64 32
```

Rotation options:

- Use `NewRotatingSecretResolver` to accept multiple secret versions for the same client.
- Deploy the new secret to clients first.
- Configure the server to accept old and new secrets during the rotation window.
- Remove the old secret after all clients have switched.

## Replay cache lifecycle

Use one replay cache per logical server instance.

Recommended patterns:

- `NewListener` / `WrapListener`: listener-owned replay cache when one is not provided; prefer `NewListener` for startup-time error handling.
- `NewServer`: server-owned replay cache when one is not provided.
- `ServerAuth`: caller must provide a shared `ReplayCache`.

Do not create a new replay cache for every connection. Replay caches fail closed when full: expired entries are swept first, and if all retained nonces are still within the replay window, new authentication material is rejected instead of evicting an active nonce. Treat replay-cache-full events as a capacity or abuse signal.

## Firewall backend selection

Recommended order:

```text
nftables
ipset-iptables
iptables
script
```

Use `noop` only for auth-only workflows and tests.

Backend notes:

| Backend | Production note |
| --- | --- |
| `nftables` | Preferred Linux backend when available. |
| `ipset-iptables` | Good fit for ipset-based environments. |
| `iptables` | Works as a fallback, but rule expiry is process-managed. |
| `script` | Use when the application must call site-specific firewall tooling. |

The plain `iptables` backend relies on revoke/cleanup timers. An unclean process exit can leave temporary rules until the next cleanup pass. Prefer `nftables` or `ipset-iptables` when kernel-enforced expiry is required.

## Service lifecycle

For gate or relay workflows that manage firewall rules:

1. Initialize the firewall backend before accepting traffic.
2. Run gate/relay under a cancellable context.
3. Cancel the context on service shutdown.
4. Call cleanup with a bounded timeout.
5. Verify cleanup behavior in the deployment environment.

Example shutdown pattern:

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

errCh := make(chan error, 1)
go func() { errCh <- gw.Run(ctx) }()

// On application shutdown:
cancel()
select {
case err := <-errCh:
    return err
case <-time.After(5 * time.Second):
    return context.DeadlineExceeded
}
```

## Linux notes

Verify:

- command availability: `nft`, `iptables`, `ipset` as applicable
- effective privileges for firewall changes
- protected port binding
- IPv4 and IPv6 behavior
- cleanup idempotency
- startup cleanup after an unclean shutdown
- UDP passive packet capture privileges when using passive UDP methods

For packet capture paths, check `CAP_NET_RAW` or equivalent privileges required by the platform.

## Windows notes

The ordinary UDP sender path is the simplest Windows client path.

TCP SYN knock paths require additional packet tooling such as WinDivert or Npcap depending on the code path and deployment. Document installer requirements and administrator privilege requirements for your product before enabling those modes.

Treat Windows support as platform-specific until it has been verified in the exact deployment environment.

## macOS notes

UDP sender paths are straightforward. Passive capture and TCP SYN paths require platform packet capabilities such as BPF/pcap or raw socket permissions.

Treat macOS packet-capture modes as platform-specific until verified on the target OS version.

## Protocol rollout

The default TCP authentication protocol is `tcp-auth-envelope-v2`.

For a controlled rollout:

1. Pick the protocol for new clients.
2. Configure servers with the intended `AcceptProtocols` set.
3. Test every accepted protocol path in CI.
4. Keep mixed-protocol windows short and explicit.
5. Remove unused accepted protocols when the rollout finishes.

## Capacity controls

Use these controls for public listeners:

- `AuthTimeout`
- `MaxFrameSize`
- `MaxAuthAttempts`
- `netx.ListenerConfig.MaxPendingAuth`
- `netx.ListenerConfig.MaxAuthWorkers`
- `Policy` hook
- relay `MaxPendingAuth`
- relay `MaxAuthWorkers`
- application-level connection limits

## Logging policy

Do not log:

- raw shared secrets
- full auth frames
- sealed payload bytes
- full knock datagrams

Prefer structured logs with reason classes and no raw packet contents.

## Minimum release gate

Before a stable release, run:

```sh
go test ./...
go vet ./...
go test -race ./auth ./firewall ./knock ./netx ./policy ./protocol ./relay
go -C observability/prometheus test ./...
go -C test/integration/grpc test ./...
```

Then complete the environment checks in [Release checklist](release-checklist.md).

## Policy cache boundaries

Replay caches, knock session stores, ban lists, and rate limiters have related storage mechanics but different security semantics. `TTLLRU.Len()` reports stored entries and may include expired entries that have not been swept yet; use active counts or sweep-aware metrics when reporting pressure. Replay caches and rate limiters fail closed at capacity, while ban/session stores remain bounded TTL stores. Script firewall backends validate configured commands during `Init()` without executing allow/revoke/cleanup scripts.

Replay caches, knock session stores, ban lists, and rate limiters have related storage mechanics but different security semantics. Replay cache entries reject duplicate authentication material, knock sessions bind a prior knock to a later TCP auth event, ban lists are TTL sets for coarse policy decisions, and limiters maintain counting windows. Do not merge these concepts in production configuration or observability just because they share an internal eviction primitive.
