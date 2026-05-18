# Architecture

libknock is a TCP pre-application authentication SDK. Its core boundary is small: authenticate a connection before application bytes are consumed, expose peer metadata, and leave application protocol handling to the caller.

## Layers

- `protocol` contains wire codecs and cryptographic framing.
- `auth` validates TCP authentication frames, replay state, policy, and peer metadata.
- `netx` is the SDK listener/dialer layer. It wraps `net.Listener` and `net.Conn` without owning firewall or relay policy.
- `knock` implements active and passive knock transports.
- `gate` composes knock, firewall, session binding, and authenticated listeners for applications that can integrate libknock directly.
- `relay` protects an existing upstream service that cannot be modified to call libknock itself.
- `internal/gatewaycore` holds shared gate/relay plumbing such as listener defaults, firewall operation contexts, UDP knock listen address selection, and event emission adapters.
- `internal/cache` holds shared bounded TTL/LRU primitives used by replay and policy structures.
- `cmd/knock-proxy` is a caller of the SDK, not the owner of core library behavior.

## Boundary rule

`gate` and `relay` intentionally remain separate public packages because they solve different integration problems. Shared mechanics live under `internal/` so the public API does not grow just to remove implementation duplication.


## Connection and replay lifecycle

`NewServer`, `WrapListener`, and the `netx.AuthenticatedListener` path own one replay cache for the listener/server lifetime when the caller does not provide one. The lower-level `ServerAuth` function does not create a per-call cache because replay protection only works when nonce state is shared across connections.

On successful authentication, libknock returns a clean `net.Conn`. If the auth parser has read beyond the authentication frame, those extra bytes are preserved by an internal buffered connection so TLS, HTTP, gRPC, or custom protocols see exactly the application bytes they expect.

On authentication failure, detailed reasons are surfaced to local errors and event sinks, but the peer-facing behavior remains a quiet close with optional bounded drain and jitter. That avoids turning the TCP admission step into an oracle for client IDs, replay state, protocol selection, or timing details.

## Workspace and release artifact boundaries

The repository is a Go workspace: the root SDK module, observability module, gRPC integration module, and examples are tied together by `go.work` / `go.work.sum` so local development and CI test the current source tree consistently. Release artifacts are intentionally module-based source packages, not vendored dependency snapshots: `vendor/` is excluded, while workspace metadata stays. Compatibility code, such as legacy SYN sequence namespaces, should stay isolated behind explicit opt-in settings rather than silently expanding the default protocol surface.
