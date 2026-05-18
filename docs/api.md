# API reference

This page summarizes the public API surface used by most integrations.

## Server-side entry points

```go
func WrapListener(ln net.Listener, cfg ServerConfig) net.Listener
func NewServer(cfg ServerConfig) (*Server, error)
func ServerAuth(ctx context.Context, conn net.Conn, cfg ServerConfig) (net.Conn, *PeerInfo, error)
```

Use `WrapListener` for the common `net.Listener` workflow. Use `NewServer` when you want explicit startup validation and a server-owned replay cache. Use `ServerAuth` for custom pipelines that already own accepted connections.

`ServerAuth` is a low-level function. It requires a shared `ReplayCache` in `ServerConfig`. `NewServer` and `WrapListener` can create and own that replay cache for the server/listener lifetime.

## Client-side entry points

```go
func ClientAuth(ctx context.Context, conn net.Conn, cfg ClientConfig) error
func ClientAuthWithInfo(ctx context.Context, conn net.Conn, cfg ClientConfig) (*PeerInfo, error)

type Dialer struct {
    Base   ContextDialer
    Config ClientConfig
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error)
```

Use `Dialer` when `libknock` should create the TCP connection. Use `ClientAuth` when another component creates the TCP connection first.

If `ClientConfig.Knock` is set, `Dialer` sends the configured knock before opening the TCP connection. If the knock sender supports session binding and `ClientConfig.SessionID` is empty, `Dialer` generates a random session ID and gives it to the sender before authentication.

## Root package boundary

The root package is the small SDK surface used by most integrations:

```go
func WrapListener(ln net.Listener, cfg ServerConfig) net.Listener
func ServerAuth(ctx context.Context, conn net.Conn, cfg ServerConfig) (net.Conn, *PeerInfo, error)
func ClientAuth(ctx context.Context, conn net.Conn, cfg ClientConfig) error
type Dialer = netx.Dialer
type ServerConfig = auth.ServerConfig
type ClientConfig = auth.ClientConfig
type PeerInfo = auth.PeerInfo
func NewServer(cfg ServerConfig) (*Server, error)
func NewMemoryReplayCache(ttl time.Duration) *auth.MemoryReplayCache
func NewStaticSecretResolver(secrets map[string][]byte) auth.StaticSecrets
const MinSecretSize = auth.MinSecretSize
type SecretResolver = auth.SecretResolver
type SecretCandidate = auth.SecretCandidate
type ReplayCache = auth.ReplayCache
type KnockSender = auth.KnockSender
type SessionBoundKnockSender = auth.SessionBoundKnockSender
type KnockSessionStore = auth.KnockSessionStore
type EventSink = auth.EventSink
type Policy = auth.Policy
type FrameMeta = auth.FrameMeta
type PeerIdentity = auth.PeerIdentity
```

Gate modes, relay configuration, firewall backends, raw knock listeners, and observability helpers are intentionally accessed through their subpackages. See [API surface](api-surface.md) for the compatibility boundary.

## ServerConfig

```go
type ServerConfig struct {
    ServerPort         int
    Secrets            SecretResolver
    ReplayCache        ReplayCache
    AuthTimeout        time.Duration
    TimeWindow         time.Duration
    MaxFrameSize       int
    Protocol           AuthProtocol
    AcceptProtocols    []AuthProtocol
    EnvelopeV2         EnvelopeV2Config
    RequireKnock       bool
    KnockStore         KnockSessionStore
    ServerProof        bool
    FailDelayJitterMin time.Duration
    FailDelayJitterMax time.Duration
    DrainOnFailBytes   int
    DrainOnFailTimeout time.Duration
    MaxAuthAttempts    int
    Events             EventSink
    Policy             Policy
    OnAuthenticated    AuthenticatedCallback
}
```

Important fields:

- `ServerPort`: protected service port used in authentication metadata. Set it explicitly when NAT, proxies, or port forwarding make the local listener address differ from the authenticated service port.
- `Secrets`: resolves client secrets. Required.
- `ReplayCache`: stores accepted nonces and blocks replay within the cache window. Required when using low-level `ServerAuth` directly.
- `AuthTimeout`: authentication deadline. Default: `3s`.
- `TimeWindow`: accepted timestamp skew. Default: `30s`.
- `MaxFrameSize`: maximum TCP auth frame size accepted by the server. Default: `1024`.
- `Protocol`: preferred TCP authentication protocol. Default: `tcp-auth-envelope-v2`.
- `AcceptProtocols`: accepted TCP authentication protocols. If empty, the server accepts only `Protocol` after defaults are applied.
- `EnvelopeV2`: route hint and bucket padding options for `tcp-auth-envelope-v2`.
- `RequireKnock` and `KnockStore`: bind TCP authentication to a previous knock session.
- `ServerProof`: enables server proof on the TCP auth exchange.
- `FailDelayJitterMin` / `FailDelayJitterMax`: optional small delay before closing failed authentication attempts.
- `DrainOnFailBytes` / `DrainOnFailTimeout`: optional bounded read drain on failed authentication.
- `MaxAuthAttempts`: maximum envelope v2 candidate/bucket AEAD attempts per connection. Default: `64`.
- `Events`: receives authentication events.
- `Policy`: optional limiter/ban hook.
- `OnAuthenticated`: callback invoked after successful authentication.

## ClientConfig

```go
type ClientConfig struct {
    ClientID           string
    Secret             []byte
    ServerPort         int
    AuthTimeout        time.Duration
    Protocol           AuthProtocol
    EnvelopeV2         EnvelopeV2Config
    Knock              KnockSender
    Method             string
    SessionID          []byte
    Extensions         []byte
    RequireServerProof bool
}
```

Important fields:

- `ClientID` and `Secret`: client identity and shared secret. Secret length must be at least 16 bytes.
- `ServerPort`: protected service port used in authentication metadata.
- `AuthTimeout`: authentication deadline. Default: `3s`.
- `Protocol`: selected TCP authentication protocol. Default: `tcp-auth-envelope-v2`.
- `EnvelopeV2`: route hint and bucket padding options for `tcp-auth-envelope-v2`.
- `Knock`: optional pre-dial knock sender.
- `Method`: method label carried in authenticated metadata.
- `SessionID`: binds TCP authentication to a prior knock session when enabled.
- `Extensions`: authenticated opaque metadata carried in the frame.
- `RequireServerProof`: requires the server proof response.

## Protocol selectors

Protocol selectors live in `github.com/libknock/libknock/auth`.

```go
clientCfg.Protocol = auth.AuthProtocolEnvelopeV2
serverCfg.Protocol = auth.AuthProtocolEnvelopeV2
serverCfg.AcceptProtocols = []auth.AuthProtocol{
    auth.AuthProtocolEnvelopeV2,
}
```

During a controlled migration, a server may accept both protocols. Keep the rollout window explicit and test both paths.

## Envelope v2 options

```go
type EnvelopeV2Config struct {
    HintMode         EnvelopeV2HintMode
    FrameSizeBuckets []int
    PaddingPolicy    EnvelopeV2PaddingPolicy
}
```

Common values are exposed by the `auth` package:

```go
auth.HintModeNone
auth.HintModeRouteHint
auth.PaddingPolicyNone
auth.PaddingPolicyRandomBucket
```

`HintModeRouteHint` is the default and recommended mode. `HintModeNone` is appropriate only for small client sets or resolvers that apply deterministic candidate limits. Built-in static and rotating resolvers return candidates sorted by `client_id`; if a no-hint candidate set exceeds `ServerConfig.MaxAuthAttempts`, authentication fails with `auth.ErrTooManyCandidates` instead of depending on map iteration order.

Default buckets are:

```text
128, 192, 256, 384, 512
```

The client builder validates envelope v2 against the envelope v2 default maximum size. The server also validates configured buckets against `ServerConfig.MaxFrameSize`.

## Secret resolvers

```go
type SecretResolver interface {
    ResolveCandidates(meta FrameMeta) ([]SecretCandidate, error)
}

type SecretCandidate struct {
    ClientID string
    Secret   []byte
}
```

Built-in resolvers:

```go
libknock.NewStaticSecretResolver(map[string][]byte{...})
auth.NewRotatingSecretResolver(map[string][][]byte{...})
```

Use `auth.RotatingSecrets` to accept multiple secret versions for the same client during a controlled key rotation window.

## Replay cache

```go
type ReplayCache interface {
    CheckAndMark(clientID string, nonce []byte) error
}

func NewMemoryReplayCache(ttl time.Duration) *MemoryReplayCache
```

Use one replay cache per logical server instance. The TTL should be longer than the accepted timestamp window.

Recommended default:

```go
ReplayCache: libknock.NewMemoryReplayCache(2 * time.Minute)
```

For `TimeWindow=30s`, a cache TTL of `1m` or longer is reasonable. Longer TTLs provide a wider replay rejection window at the cost of memory.

## Peer metadata

```go
type PeerInfo struct {
    PeerIdentity
    KeyHint    uint64
    Nonce      []byte
    Timestamp  int64
    ServerPort int
    Method     string
    SessionID  []byte
    Extensions []byte
    RemoteAddr net.Addr
    Protocol   AuthProtocol
    Flags      byte
}
```

Helpers:

```go
type PeerInfoProvider interface {
    PeerInfo() PeerInfo
}

func PeerFromConn(conn net.Conn) (PeerInfo, bool)
func ContextWithPeer(ctx context.Context, peer PeerInfo) context.Context
func PeerFromContext(ctx context.Context) (PeerInfo, bool)
func ConnContextWithPeer(ctx context.Context, conn net.Conn) context.Context
```

For HTTP servers, `ConnContextWithPeer` can be used from `http.Server.ConnContext` before the connection is wrapped by higher application layers.

## Events

```go
type EventSink interface {
    OnAccept(remote net.Addr)
    OnAuthOK(peer PeerInfo)
    OnAuthFail(remote net.Addr, reason error)
    OnReplay(remote net.Addr, peerHint uint64)
    OnRateLimited(remote net.Addr)
}
```

Applications decide how to log, count, sample, or export these events.

## Policy hook

```go
type Policy interface {
    Allow(key string) bool
}
```

`Policy` is called before authentication work. Use it for in-memory admission limits, temporary bans, or custom rate-control adapters.

## Advanced subpackages

- `auth`: protocol selectors, advanced resolver/cache interfaces, policy hooks, peer context helpers, and auth error values.
- `gate`: listener composition modes such as `gate.AuthOnly`, `gate.KnockAuthOnly`, `gate.KnockFirewallAuth`, and `gate.KnockFirewallOnly`.
- `relay`: proxy-style gateway for services that use a separate upstream listener.
- `firewall`: platform firewall backend interfaces and implementations.
- `knock`: binary knock senders/listeners.
- `observability`: shared event interfaces and event payloads.

Example gate use:

```go
g, err := gate.New(gate.Config{
    Mode: gate.KnockAuthOnly,
    Auth: libknock.ServerConfig{ServerPort: 9000, Secrets: libknock.NewStaticSecretResolver(secrets)},
    KnockMethod: knock.UDPMethod,
    KnockClients: []knock.ClientSecret{{ClientID: "client-001", Secret: secret}},
})
```
