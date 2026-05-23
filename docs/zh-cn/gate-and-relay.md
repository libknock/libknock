# Gate 和 relay

`libknock` 提供两种组合方式：

- `gate`：为嵌入 SDK 的应用包装或创建一个 `net.Listener`。
- `relay`：在另一个 TCP 服务前运行 TCP 转发网关。

## Gate 模式

```go
type GateMode string

const (
    GateAuthOnly          GateMode = "auth-only"
    GateKnockAuthOnly     GateMode = "knock-auth-only"
    GateKnockFirewallAuth GateMode = "knock-firewall-auth"
    GateKnockFirewallOnly GateMode = "knock-firewall-only"
)
```

| 模式 | 监听器行为 | 是否需要防火墙 | 是否需要 TCP 认证 |
| --- | --- | ---: | ---: |
| `auth-only` | 使用 TCP 认证包装监听器。 | 否 | 是 |
| `knock-auth-only` | 启动敲门监听器，记录短期敲门会话，然后要求 TCP 认证必须匹配该会话。TCP 端口在传输层保持打开。 | 否 | 是 |
| `knock-firewall-auth` | 启动敲门监听器，为通过的客户端打开防火墙访问，然后要求 TCP 认证。 | 是 | 是 |
| `knock-firewall-only` | 启动敲门监听器，为通过的客户端打开防火墙访问，然后接受匹配的 TCP 连接。 | 是 | 否 |

`knock-auth-only` 不修改防火墙规则。TCP listener visibility remains unchanged；未认证客户端可以完成 TCP 握手，但只有同时通过 knock 和 TCP 认证后才能进入应用协议。它适合无防火墙权限或不希望控制防火墙的环境；需要 firewall gate 时仍应使用 `knock-firewall-auth`。

`knock-firewall-auth` 和 `knock-firewall-only` 需要非 noop 的防火墙后端。`auth-only` 和 `knock-auth-only` 可以使用 `firewall.Noop{}`。


## Knock + Auth-only

`knock-auth-only` 要求客户端先发送有效 knock，服务端创建短期会话，随后同一客户端在 TCP 认证中匹配并消费该会话后，应用才会收到 clean `net.Conn`。该模式不调用防火墙 `Init`、`Allow`、`Revoke` 或 `Cleanup`，因此不需要 root 或 `CAP_NET_ADMIN`。

TCP listener visibility remains unchanged；应用协议准入仍要求合法 auth frame。未认证连接可能表现为 `unknown`、连接关闭或无有效应用协议响应。它比 `auth-only` 多一个 knock session 前置条件，但不替代需要 firewall gate 语义的 `knock-firewall-auth`。

## GateConfig

```go
type GateConfig struct {
    Mode                   GateMode
    Listen                 string
    Auth                   auth.ServerConfig
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
```

重要字段：

- `Mode`：gate 模式。
- `Listen`：使用 `ListenGate` 或 `Gate.Listen` 时的 TCP 监听地址。
- `Auth`：服务端 TCP 认证配置。
- `Listener`：认证监听器的队列和 worker 限制。
- `Firewall`：敲门/防火墙模式的防火墙后端。
- `KnockMethod`：受支持的敲门方法名称之一。
- `KnockListen`：显式的敲门监听地址。
- `KnockPort`：派生默认敲门监听地址时使用的敲门端口。
- `KnockClients`：敲门监听器接受的客户端 ID 和密钥。
- `AllowTTL`：防火墙租约持续时间。未设置时，默认行为使用较短租约。重复的有效敲门会从最后一次接受的敲门开始续签防火墙放行窗口。
- `MaxConnectionsPerKnock`：每个敲门会话接受的 TCP 连接数。
- `Events`：网关级事件接收器。

## 使用 Gate 创建监听器

```go
g, err := gate.New(gate.Config{
    Mode:   gate.AuthOnly,
    Listen: ":9000",
    Auth:   serverAuthConfig,
})
if err != nil {
    return err
}

ln, err := g.Listen(ctx)
if err != nil {
    return err
}
```

## 包装现有监听器

```go
base, err := net.Listen("tcp", ":9000")
if err != nil {
    return err
}

g, err := gate.New(gateConfig)
if err != nil {
    return err
}

ln, err := g.Wrap(ctx, base)
if err != nil {
    return err
}
```

## 显式选择加入的应用配置

带配置开关的应用应在自己的配置层保留开关，并且只在启用时调用 `gate.Listen` 或 `gate.New(...).Wrap`。

```go
ln, err := net.Listen("tcp", app.Listen)
if err != nil {
    return err
}
if app.Libknock.Enabled {
    g, err := gate.New(gateConfig)
    if err != nil {
        return err
    }
    ln, err = g.Wrap(ctx, ln)
    if err != nil {
        return err
    }
}
```

这样根包 API 保持小而明确，应用启动策略也不会隐藏在便利层里。

## 敲门 + 防火墙 + 认证

当服务器应要求敲门会话和 TCP 认证帧时，使用 `GateKnockFirewallAuth`。

```go
g, err := gate.New(gate.Config{
    Mode:        gate.KnockFirewallAuth,
    Listen:      ":9000",
    Auth:        serverAuthConfig,
    Firewall:    fw,
    KnockMethod: "udp",
    KnockPort:   10000,
    KnockClients: []knock.ClientSecret{
        {ClientID: "client-001", Secret: secret},
    },
    AllowTTL:               30 * time.Second,
    MaxConnectionsPerKnock: 1,
})
```

成功敲门会创建一个短生命周期会话。当拨号器和敲门发送方启用会话绑定时，随后的 TCP 认证帧必须携带匹配的客户端身份和会话 ID。

## 仅敲门 + 防火墙

当应用协议无法发送 `libknock` TCP 认证帧时，使用 `GateKnockFirewallOnly`。

```go
g, err := gate.New(gate.Config{
    Mode:        gate.KnockFirewallOnly,
    Listen:      ":9000",
    Firewall:    fw,
    KnockMethod: "udp",
    KnockPort:   10000,
    KnockClients: []knock.ClientSecret{
        {ClientID: "client-001", Secret: secret},
    },
})
```

此模式仅通过敲门和防火墙提供监听器准入。它不执行 TCP 载荷认证。

## Relay 网关

`relay.Gateway` 监听一个 TCP 地址，并将接受的连接转发到上游 TCP 地址。

```go
gw := relay.Gateway{
    Listen:   ":9000",
    Upstream: "127.0.0.1:19000",
    Auth:     serverAuthConfig,
    Firewall: firewall.Noop{},
}

if err := gw.Run(ctx); err != nil {
    return err
}
```

常用字段：

```go
type Gateway struct {
    Listen                 string
    Upstream               string
    Auth                   auth.ServerConfig
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
    UpstreamConnectTimeout time.Duration
    IdleTimeout            time.Duration
    RemoveAfterAuth        bool
    MaxConnectionsPerKnock int
    DisableSessionBinding  bool
    MaxPendingAuth         int
    MaxAuthWorkers         int
    Events                 relay.EventSink
}
```

`MaxPendingAuth` 和 `MaxAuthWorkers` 限制并发认证工作。`UpstreamConnectTimeout` 限制上游连接建立时间。`IdleTimeout` 限制不活跃的中继连接。

## 模式选择

| 场景 | 建议组件 |
| --- | --- |
| 应用可以包装自己的监听器 | `WrapListener` 或 `GateAuthOnly` |
| 应用需要敲门 + 防火墙 + TCP 认证 | `GateKnockFirewallAuth` |
| 应用需要敲门 + 防火墙监听器准入 | `GateKnockFirewallOnly` |
| 独立上游 TCP 服务应位于转发网关后面 | `relay.Gateway` |

## 生命周期

对于管理防火墙规则的 gate 和 relay 模式，请在应用关闭期间会取消的上下文下运行它们。当应用拥有 `Gate` 值并需要显式清理时，调用 `Gate.Close(ctx)`。

在可用时使用服务管理器关闭钩子。对于普通的 `iptables` 后端，这尤其重要，因为规则过期依赖进程管理的计时器和清理。
