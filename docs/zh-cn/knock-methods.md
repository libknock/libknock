# 敲门方法支持

敲门方法是由 `gate` 和 `relay` 使用的可选组件。它们在 `knock` 包中实现，也可以通过 `knock.SendMethod` 直接调用。

## 支持的方法

| 方法 | 摘要 | 客户端侧 | 服务端侧 |
| --- | --- | --- | --- |
| `tcp-syn` | 单个 TCP SYN 敲门。 | Linux raw socket、Windows WinDivert/Npcap、macOS raw socket。 | Linux raw socket、macOS BPF。 |
| `tcp-syn-seq` | 多部分 TCP SYN 序列敲门。 | Linux raw socket、Windows WinDivert/Npcap、macOS raw socket。 | Linux raw socket、macOS BPF。 |
| `udp` | 单个 UDP 敲门。 | 标准 UDP socket。 | 标准 UDP socket。 |
| `udp-seq` | 多部分 UDP 序列敲门。 | 标准 UDP socket。 | 标准 UDP socket。 |
| `udp-passive` | 服务端通过包捕获读取的 UDP 敲门。 | 标准 UDP 发送方。 | Linux AF_PACKET 或 macOS BPF。 |
| `udp-passive-seq` | 服务端通过包捕获读取的多部分 UDP 序列。 | 标准 UDP 序列发送方。 | Linux AF_PACKET 或 macOS BPF。 |

## 配置 UI 的方法顺序

展示方法选择时使用此顺序：

```text
tcp-syn
tcp-syn-seq
udp
udp-seq
udp-passive
udp-passive-seq
```

## 客户端分派

```go
err := knock.SendMethod(ctx, "udp-seq", knock.SendOptions{
    ServerAddr: "server.example.com:10000",
    ClientID:   "client-001",
    Secret:     secret,
    ServerPort: 9000,
    Sequence: knock.SequenceOptions{
        Length:         3,
        PacketInterval: 80 * time.Millisecond,
    },
})
```

接受的方法别名：

- `udp-sequence` 映射到 `udp-seq`。

## UDP 方法

`udp` 发送一个 UDP 数据报。`udp-seq` 发送多个共享同一序列 ID 的 UDP 数据报。服务器只有在所有部分都在序列窗口内到达后才会完成序列。

序列默认值：

| 字段 | 默认值 |
| --- | --- |
| `Window` | `5s` |
| `DefaultSequenceMaxParts` | `8` |

当单个经过认证的数据报足够时，使用 `udp`。当部署希望在创建准入会话前接收多个短窗口数据报时，使用 `udp-seq`。

## UDP 被动方法

`udp-passive` 和 `udp-passive-seq` 在服务端通过包捕获读取 UDP 敲门流量，而不是通过普通 UDP 监听器。这些模式要求服务端平台具备包捕获权限。

仅当部署能够提供所需的平台能力和防火墙配置时，才使用被动 UDP。生命周期和能力说明见 [防火墙后端](firewall.md) 和 [生产部署](production.md)。

## TCP SYN 方法

`tcp-syn` 使用一个 SYN 形态的敲门。`tcp-syn-seq` 使用多个部分。这些方法要求参与的平台路径具备原始数据包能力。

平台说明：

| 平台 | 说明 |
| --- | --- |
| Linux | TCP SYN 路径需要 raw socket 能力。 |
| Windows | 高级 TCP SYN 路径优先使用 WinDivert；Npcap 回退取决于本地安装和权限。 |
| macOS | 根据路径不同，需要 raw socket 或 BPF/pcap 能力。 |

对于短窗口重连工作流，序列方法比单个确定性敲门提供更好的运维行为。

## 会话绑定

敲门方法可以携带 `session_id`。使用 `GateKnockFirewallAuth` 或 relay 会话绑定时，随后的 TCP 认证帧必须携带匹配的会话 ID。这会将敲门事件和 TCP 认证事件绑定到同一个短生命周期准入记录。

`netx.Dialer` 可以生成随机会话 ID，并将其传递给实现会话绑定发送方接口的敲门发送方。

## 直接使用包

监听器 API 接受类型化选项：

```go
type ListenOptions struct {
    Port             int
    KnockPort        int
    Clients          []ClientSecret
    TimeWindow       time.Duration
    MaxFrameSize     int
    RequireSessionID bool
    ReplayCache      auth.ReplayCache
    AllowPacket      func(net.IP) bool
    InvalidPacket    func(net.IP, string)
    Sequence         SequenceOptions
    NonceTTL         time.Duration
}
```

发送方 API 接受类型化选项：

```go
type SendOptions struct {
    ServerAddr   string
    ClientID     string
    Secret       []byte
    ServerPort   int
    TimeWindow   time.Duration
    MaxFrameSize int
    Sequence     SequenceOptions
    SessionID    []byte
}
```

## 选择指南

| 需求 | 推荐方法 |
| --- | --- |
| 最简单的跨平台设置 | `udp` |
| 多部分 UDP 准入 | `udp-seq` |
| 服务端包捕获路径 | `udp-passive` 或 `udp-passive-seq` |
| TCP SYN 形态敲门路径 | `tcp-syn` |
| 多部分 TCP SYN 形态准入 | `tcp-syn-seq` |

除非部署有使用其他方法的特定理由，否则从 `udp` 开始。
