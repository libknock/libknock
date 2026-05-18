# Troubleshooting

This document lists common integration and deployment failures.

## Authentication fails immediately

Check:

- client and server use the same `ServerPort`
- client ID exists in the server `SecretResolver`
- secret bytes are identical after decoding from application config
- client and server `Protocol` / `AcceptProtocols` overlap
- client clock is inside the server `TimeWindow`
- server has a shared `ReplayCache`
- `MaxFrameSize` is large enough for the selected protocol and metadata

For direct `ServerAuth` use, missing `ReplayCache` returns `ErrMissingReplayCache`.

## First connection succeeds, reconnect fails

Possible causes:

- replay cache is rejecting reused nonces from a test client
- knock session was configured for one use only
- `RemoveAfterAuth` revoked the session after first authentication
- `MaxConnectionsPerKnock` is set to `1`

Generate a new auth frame for every TCP connection. Do not reuse a serialized frame.

## TLS handshake fails after libknock auth

Check:

- server wraps listener in this order: base TCP listener -> `libknock.WrapListener` -> `tls.NewListener`
- client dials in this order: `libknock.Dialer` -> `tls.Client`
- `ServerPort` matches the protected service port
- the client is not sending application protocol bytes before `ClientAuth`

`libknock` returns a clean `net.Conn` after authentication. If authentication code is modified, preserve buffered bytes so the application protocol still receives its complete first message.

## gRPC client cannot connect

Check:

- the server listener is wrapped before TLS and before `grpc.Server.Serve`
- the client transport dials through `libknock.Dialer` before TLS
- the gRPC integration module tests pass:

```sh
go -C test/integration/grpc test ./...
```

## Gate mode starts but firewall does nothing

Check:

- `GateKnockFirewallAuth` and `GateKnockFirewallOnly` require a non-noop firewall backend
- `firewall.Config.Port` or the injected listener port is correct
- the process has privileges to install firewall rules
- backend commands are installed
- `firewall.Probe` succeeds

## iptables rules remain after shutdown

The plain `iptables` backend relies on process-managed revoke and cleanup. If the process exits unexpectedly, temporary rules may remain until the next cleanup pass.

Mitigations:

- prefer `nftables` or `ipset-iptables` where available
- run cleanup on controlled shutdown
- run startup cleanup before accepting traffic
- use a dedicated chain name for `libknock`

## UDP passive mode does not receive knocks

Check:

- server platform supports the passive backend in use
- process has packet capture privileges
- network interface selection is correct
- `DropUDPKnockPort` is only used with passive UDP methods
- firewall backend supports the required UDP drop behavior
- the knock is sent to the expected knock port

## TCP SYN method fails

Check platform-specific packet capability:

- Linux: raw socket capability
- Windows: WinDivert or Npcap installation and administrator privilege
- macOS: raw socket or BPF/pcap capability

If operational simplicity matters more than TCP SYN knock semantics, start with `udp`.

## Secret resolver errors are indistinguishable from auth failures externally

Network behavior is intentionally close-only on authentication failure. Internally, SDK errors and `EventSink` reasons can distinguish resolver failures, unknown clients, replay, time skew, unsupported protocol, unsupported flags, and rate limits.

Do not expose detailed failure reasons to network peers.

## Prometheus label cardinality grows unexpectedly

Check:

- `IncludeClientLabel` is disabled unless client count is bounded
- method labels are normalized to the supported method names or `unknown`
- remote address is not used as a label

## CI fails because nested modules are not tested

Run nested module tests explicitly:

```sh
go test ./...
go -C observability/prometheus test ./...
go -C test/integration/grpc test ./...
```

The main release path uses Go modules. Source archives do not include vendor/, so offline builds need a populated module cache or an internal dependency mirror.
