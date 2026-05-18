# API 参考

本页总结大多数集成会用到的公共 API 表面。

## 服务器端入口点

```go
func WrapListener(ln net.Listener, cfg ServerConfig) net.Listener
func NewServer(cfg ServerConfig) (*Server, error)
func ServerAuth(ctx context.Context, conn net.Conn, cfg ServerConfig) (net.Conn, *PeerInfo, error)
```

常见的 `net.Listener` 工作流请使用 `WrapListener`。当你希望进行显式启动校验并使用由服务器拥有的重放缓存时，请使用 `NewServer`。对于已经自行拥有已接受连接的自定义流水线，请使用 `ServerAuth`。

`ServerAuth` 是低层函数。它要求在 `ServerConfig` 中提供共享的 `ReplayCache`。`NewServer` 和 `WrapListener` 可以为服务器/监听器生命周期创建并持有该重放缓存。

## 客户端入口点

```go
func ClientAuth(ctx context.Context, conn net.Conn, cfg ClientConfig) error
func ClientAuthWithInfo(ctx context.Context, conn net.Conn, cfg ClientConfig) (*PeerInfo, error)

type Dialer struct {
    Base   ContextDialer
    Config ClientConfig
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error)
```

当应由 `libknock` 创建 TCP 连接时，使用 `Dialer`。当另一个组件先创建 TCP 连接时，使用 `ClientAuth`。

如果设置了 `ClientConfig.Knock`，`Dialer` 会在打开 TCP 连接之前发送配置的 knock。如果 knock 发送器支持会话绑定且 `ClientConfig.SessionID` 为空，`Dialer` 会生成随机会话 ID，并在认证前交给发送器。

## 根包边界

根包只保留多数集成会用到的小型 SDK 面：

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

Gate 模式、relay 配置、防火墙后端、原始 knock listener 和 observability helper 均通过对应子包访问。参见英文版 [API surface](../api-surface.md) 了解兼容性边界。

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

重要字段：

- `ServerPort`：认证元数据中使用的受保护服务端口。当 NAT、代理或端口转发导致本地监听地址与已认证服务端口不同时，请显式设置它。
- `Secrets`：解析客户端密钥。必需。
- `ReplayCache`：保存已接受的 nonce，并在缓存窗口内阻止重放。直接使用低层 `ServerAuth` 时必需。
- `AuthTimeout`：认证截止时间。默认值：`3s`。
- `TimeWindow`：接受的时间戳偏移。默认值：`30s`。
- `MaxFrameSize`：服务器接受的最大 TCP 认证帧大小。默认值：`1024`。
- `Protocol`：首选 TCP 认证协议。默认值：`tcp-auth-envelope-v2`。
- `AcceptProtocols`：接受的 TCP 认证协议。如果为空，应用默认值后服务器只接受 `Protocol`。
- `EnvelopeV2`：`tcp-auth-envelope-v2` 的路由提示和桶填充选项。
- `RequireKnock` 和 `KnockStore`：将 TCP 认证绑定到之前的 knock 会话。
- `ServerProof`：在 TCP 认证交换中启用服务器证明。
- `FailDelayJitterMin` / `FailDelayJitterMax`：认证失败后关闭连接前的可选小延迟。
- `DrainOnFailBytes` / `DrainOnFailTimeout`：认证失败后的可选有界读取排空。
- `MaxAuthAttempts`：每个连接的最大 envelope v2 候选/桶 AEAD 尝试次数。默认值：`64`。
- `Events`：接收认证事件。
- `Policy`：可选的限流/封禁钩子。
- `OnAuthenticated`：认证成功后调用的回调。

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

重要字段：

- `ClientID` 和 `Secret`：客户端身份与共享密钥。密钥长度必须至少为 16 字节。
- `ServerPort`：认证元数据中使用的受保护服务端口。
- `AuthTimeout`：认证截止时间。默认值：`3s`。
- `Protocol`：所选 TCP 认证协议。默认值：`tcp-auth-envelope-v2`。
- `EnvelopeV2`：`tcp-auth-envelope-v2` 的路由提示和桶填充选项。
- `Knock`：可选的拨号前 knock 发送器。
- `Method`：在已认证元数据中携带的方法标签。
- `SessionID`：启用时，将 TCP 认证绑定到先前的 knock 会话。
- `Extensions`：帧中携带的已认证不透明元数据。
- `RequireServerProof`：要求服务器证明响应。

## 协议选择器

```go
type AuthProtocol string

const (
    AuthProtocolFrameV1    AuthProtocol = "tcp-auth-frame-v1"
    AuthProtocolEnvelopeV2 AuthProtocol = "tcp-auth-envelope-v2"
    DefaultAuthProtocol                 = AuthProtocolEnvelopeV2
)
```

客户端选择：

```go
clientCfg.Protocol = auth.AuthProtocolEnvelopeV2
```

服务器选择：

```go
serverCfg.Protocol = auth.AuthProtocolEnvelopeV2
serverCfg.AcceptProtocols = []auth.AuthProtocol{
    auth.AuthProtocolEnvelopeV2,
}
```

在受控迁移期间，服务器可以同时接受两种协议。请明确迁移窗口，并测试两条路径。

## Envelope v2 选项

```go
type EnvelopeV2Config struct {
    HintMode         EnvelopeV2HintMode
    FrameSizeBuckets []int
    PaddingPolicy    EnvelopeV2PaddingPolicy
}
```

从根包暴露的常用值：

```go
auth.HintModeNone
auth.HintModeRouteHint
auth.PaddingPolicyNone
auth.PaddingPolicyRandomBucket
```

`HintModeRouteHint` 是默认且推荐的模式。`HintModeNone` 仅适用于小型客户端集合，或会自行应用确定性候选限制的解析器。内置 static / rotating resolver 会按 `client_id` 排序候选；如果 no-hint 候选数超过 `ServerConfig.MaxAuthAttempts`，认证会返回 `auth.ErrTooManyCandidates`，而不是依赖 map 迭代顺序。

默认桶为：

```text
128, 192, 256, 384, 512
```

客户端构建器会根据 envelope v2 默认最大大小校验 envelope v2。服务器也会根据 `ServerConfig.MaxFrameSize` 校验配置的桶。

## 密钥解析器

```go
type SecretResolver interface {
    ResolveCandidates(meta FrameMeta) ([]SecretCandidate, error)
}

type SecretCandidate struct {
    ClientID string
    Secret   []byte
}
```

内置解析器：

```go
libknock.NewStaticSecretResolver(map[string][]byte{...})
auth.NewRotatingSecretResolver(map[string][][]byte{...})
```

在受控密钥轮换窗口中，使用 `RotatingSecrets` 接受同一客户端的多个密钥版本。

## 重放缓存

```go
type ReplayCache interface {
    CheckAndMark(clientID string, nonce []byte) error
}

func NewMemoryReplayCache(ttl time.Duration) *MemoryReplayCache
```

每个逻辑服务器实例使用一个重放缓存。TTL 应长于接受的时间戳窗口。

推荐默认值：

```go
ReplayCache: libknock.NewMemoryReplayCache(2 * time.Minute)
```

对于 `TimeWindow=30s`，`1m` 或更长的缓存 TTL 是合理的。更长的 TTL 会以更多内存为代价提供更宽的重放拒绝窗口。

## 对端元数据

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

辅助函数：

```go
type PeerInfoProvider interface {
    PeerInfo() PeerInfo
}

func PeerFromConn(conn net.Conn) (PeerInfo, bool)
func ContextWithPeer(ctx context.Context, peer PeerInfo) context.Context
func PeerFromContext(ctx context.Context) (PeerInfo, bool)
func ConnContextWithPeer(ctx context.Context, conn net.Conn) context.Context
```

对于 HTTP 服务器，可以在连接被更高层应用包装之前，从 `http.Server.ConnContext` 使用 `ConnContextWithPeer`。

## 事件

```go
type EventSink interface {
    OnAccept(remote net.Addr)
    OnAuthOK(peer PeerInfo)
    OnAuthFail(remote net.Addr, reason error)
    OnReplay(remote net.Addr, peerHint uint64)
    OnRateLimited(remote net.Addr)
}
```

应用程序决定如何记录、计数、采样或导出这些事件。

## Policy 钩子

```go
type Policy interface {
    Allow(key string) bool
}
```

`Policy` 会在认证工作之前调用。可将其用于内存准入限制、临时封禁或自定义速率控制适配器。

## Gate API

```go
type GateConfig struct {
    Mode                   GateMode
    Listen                 string
    Auth                   ServerConfig
    Listener               netx.ListenerConfig
    Firewall               firewall.Backend
    KnockMethod            string
    KnockListen            string
    KnockPort              int
    KnockClients           []knock.ClientSecret
    KnockTimeWindow        time.Duration
    KnockMaxFrameSize      int
    KnockSequence          knock.SequenceOptions
    KnockNonceTTL          time.Duration
    AllowTTL               time.Duration
    MaxConnectionsPerKnock int
    Events                 observability.GatewayEvents
}

func NewGate(cfg GateConfig) (*Gate, error)
func ListenGate(ctx context.Context, cfg GateConfig) (net.Listener, error)
```

仅需要 TCP 认证时，使用 `GateAuthOnly`。需要客户端先 knock、再通过 TCP 认证但 SDK 不修改防火墙规则时，使用 `GateKnockAuthOnly`。当准入路径包含 knock 监听器和防火墙后端时，使用 `GateKnockFirewallAuth` 或 `GateKnockFirewallOnly`。
