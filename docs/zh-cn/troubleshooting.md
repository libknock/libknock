# 故障排查

本文档列出常见的集成和部署故障。

## 认证立即失败

检查：

- 客户端和服务端使用相同的 `ServerPort`
- 客户端 ID 存在于服务端 `SecretResolver` 中
- 从应用配置解码后，密钥字节完全相同
- 客户端和服务端的 `Protocol` / `AcceptProtocols` 有交集
- 客户端时钟位于服务端 `TimeWindow` 内
- 服务端有共享的 `ReplayCache`
- `MaxFrameSize` 对所选协议和元数据足够大

对于直接使用 `ServerAuth` 的情况，缺少 `ReplayCache` 会返回 `ErrMissingReplayCache`。

## 第一次连接成功，重连失败

可能原因：

- 重放缓存拒绝了测试客户端复用的 nonce
- knock 会话被配置为只能使用一次
- `RemoveAfterAuth` 在第一次认证后撤销了会话
- `MaxConnectionsPerKnock` 设置为 `1`

为每个 TCP 连接生成新的认证帧。不要复用已序列化的帧。

## libknock 认证后 TLS 握手失败

检查：

- 服务端按此顺序包装监听器：base TCP listener -> `libknock.WrapListener` -> `tls.NewListener`
- 客户端按此顺序拨号：`libknock.Dialer` -> `tls.Client`
- `ServerPort` 与受保护的服务端口匹配
- 客户端没有在 `ClientAuth` 前发送应用协议字节

`libknock` 在认证后返回干净的 `net.Conn`。如果修改认证代码，请保留已缓冲字节，以便应用协议仍能收到完整的第一条消息。

## gRPC 客户端无法连接

检查：

- 服务端监听器先被包装，再进入 TLS 和 `grpc.Server.Serve`
- 客户端传输在 TLS 前通过 `libknock.Dialer` 拨号
- gRPC 集成模块测试通过：

```sh
go -C test/integration/grpc test ./...
```

## Gate 模式启动但防火墙无动作

检查：

- `GateKnockFirewallAuth` 和 `GateKnockFirewallOnly` 需要非 noop 的防火墙后端
- `firewall.Config.Port` 或注入的监听器端口正确
- 进程有安装防火墙规则的权限
- 已安装后端命令
- `firewall.Probe` 成功

## iptables 规则在关闭后仍保留

普通 `iptables` 后端依赖进程管理的撤销和清理。如果进程意外退出，临时规则可能会保留到下一次清理流程。

缓解措施：

- 在可用时优先使用 `nftables` 或 `ipset-iptables`
- 在受控关闭时运行清理
- 在接受流量前运行启动清理
- 为 `libknock` 使用专用链名

## UDP 被动模式收不到 knocks

检查：

- 服务端平台支持正在使用的被动后端
- 进程具备包捕获权限
- 网络接口选择正确
- `DropUDPKnockPort` 仅与被动 UDP 方法一起使用
- 防火墙后端支持所需的 UDP drop 行为
- knock 被发送到预期的 knock 端口

## TCP SYN 方法失败

检查平台特定的数据包能力：

- Linux：原始套接字能力
- Windows：WinDivert 或 Npcap 安装，以及管理员权限
- macOS：原始套接字或 BPF/pcap 能力

如果操作简单性比 TCP SYN knock 语义更重要，请从 `udp` 开始。

## 密钥解析器错误在外部与认证失败无法区分

认证失败时，网络行为有意仅表现为关闭连接。在内部，SDK 错误和 `EventSink` 原因可以区分解析器失败、未知客户端、重放、时间偏移、协议不支持、标志不支持以及速率限制。

不要向网络对等方暴露详细失败原因。

## Prometheus 标签基数意外增长

检查：

- 除非客户端数量有界，否则禁用 `IncludeClientLabel`
- method 标签被规范化为支持的方法名或 `unknown`
- 远端地址未被用作标签

## CI 因未测试嵌套模块而失败

显式运行嵌套模块测试：

```sh
go test ./...
go -C observability/prometheus test ./...
go -C test/integration/grpc test ./...
```

主发布路径使用 Go modules。源码包不包含 vendor/，离线构建需要预先准备本地 module cache 或内部依赖镜像。
