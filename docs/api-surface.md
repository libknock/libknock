# API surface

`libknock` intentionally separates the stable SDK path from advanced protocol and platform packages.

## Stable root package

Use the root package for normal TCP service integration:

- listener wrapping: `NewListener`, `WrapListener`, `WrapListenerE`
- explicit server object: `NewServer`, `Server`
- one-shot auth: `ServerAuth`, `ClientAuth`
- client dialing: `Dialer`
- configuration and metadata: `ServerConfig`, `ClientConfig`, `PeerInfo`
- stable constants and extension interfaces: `MinSecretSize`, `SecretResolver`, `SecretCandidate`, `ReplayCache`, `KnockSender`, `SessionBoundKnockSender`, `KnockSessionStore`, `EventSink`, `Policy`, `FrameMeta`, `PeerIdentity`


Stable root export snapshot for automated checks:

```api-snapshot root
ClientAuth
ClientConfig
Dialer
EventSink
FrameMeta
KnockSender
KnockSessionStore
MinSecretSize
NewListener
NewMemoryReplayCache
NewServer
NewStaticSecretResolver
PeerIdentity
PeerInfo
Policy
ReplayCache
SecretCandidate
SecretResolver
Server
ServerAuth
ServerConfig
SessionBoundKnockSender
WrapListener
WrapListenerE
```

Run `scripts/check-api.sh` before release to catch accidental removal of stable root exports. It now compares the signature-level snapshot below so function signatures, interface method sets, exported struct fields, and const/var declarations cannot drift silently.

```api-signature-snapshot root
const MinSecretSize = auth.MinSecretSize
func ClientAuth(ctx context.Context, conn net.Conn, cfg ClientConfig) error
func NewListener(ln net.Listener, cfg ServerConfig) (net.Listener, error)
func NewMemoryReplayCache(ttl time.Duration) *auth.MemoryReplayCache
func NewServer(cfg ServerConfig) (*Server, error)
func NewStaticSecretResolver(secrets map[string][]byte) auth.StaticSecrets
func ServerAuth(ctx context.Context, conn net.Conn, cfg ServerConfig) (net.Conn, *PeerInfo, error)
func WrapListener(ln net.Listener, cfg ServerConfig) net.Listener
func WrapListenerE(ln net.Listener, cfg ServerConfig) (net.Listener, error)
type ClientConfig auth.ClientConfig
type Dialer netx.Dialer
type EventSink auth.EventSink
type FrameMeta auth.FrameMeta
type KnockSender auth.KnockSender
type KnockSessionStore auth.KnockSessionStore
type PeerIdentity auth.PeerIdentity
type PeerInfo auth.PeerInfo
type Policy auth.Policy
type ReplayCache auth.ReplayCache
type SecretCandidate auth.SecretCandidate
type SecretResolver auth.SecretResolver
type Server auth.Server
type ServerConfig auth.ServerConfig
type SessionBoundKnockSender auth.SessionBoundKnockSender
```

## Stable advanced auth package

Use `auth` when an integration needs protocol selectors, custom secret resolution, replay cache implementations, policy hooks, events, envelope-v2 options, or knock-session binding.

`HintModeRouteHint` is the recommended default for TCP auth envelope v2. `HintModeNone` is deterministic but intended for small candidate sets; if the number of candidates exceeds `MaxAuthAttempts`, authentication fails with `ErrTooManyCandidates` instead of depending on map iteration order.

## Wire-level package

`protocol` is for advanced users who need direct frame/envelope encoding, interoperability tests, or custom transports. Its exported low-level helpers are wire-level release-candidate APIs, not the preferred stable integration surface.

## Platform packages

`knock`, `firewall`, `gate`, `relay`, and `observability` are public advanced/experimental packages. Raw packet, passive-capture, SYN, and host firewall paths require target-host validation as documented in the validation matrix and known limitations.

Coding agents should not treat these packages as the default integration surface. Start from the root package or `auth` unless the task explicitly involves knock methods, firewall mutation, gate composition, relay compatibility, or observability adapters. Do not add application config parsing, long-running service orchestration, or product-specific policy to SDK core packages.

## Command package

`cmd/knock-proxy` is maintained as a relay compatibility command. It should not be read as a complete CLI wrapper for every SDK gate mode.
