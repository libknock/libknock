# 使用场景

`libknock` 是一个可嵌入的 TCP 应用前认证 SDK，面向 Go 应用。

它提供经过认证的 `net.Listener` 和 `net.Dialer` 包装器。SDK 会在应用协议启动前验证二进制认证帧。认证成功后，调用方会收到一个干净的 `net.Conn`。

`libknock` 不解析、不修改、也不拥有应用协议。应用可以继续使用 TLS、HTTP、gRPC、私有 RPC、自定义 TCP 协议、长连接 agent 连接，或其他运行在 TCP 之上的协议。

## 私有管理端点

`libknock` 可用于保护私有管理端点、运维 API、诊断端口和内部管理服务。

```text
admin client
  -> libknock Dialer
  -> TCP pre-authentication
  -> TLS / HTTP / gRPC / custom protocol
  -> management service
```

这会让未认证连接远离应用协议解析器。

## Agent 和采集器系统

`libknock` 适用于监控 agent、日志采集器、备份 agent、资产清单 agent、维护 agent 和边缘节点客户端。

```text
agent
  -> libknock Dialer
  -> TCP pre-authentication
  -> TLS / gRPC stream / custom TCP
  -> collector or control server
```

服务端可以在将连接交给应用层之前，验证客户端身份、时间戳窗口、nonce 重放状态和客户端密钥。

## 私有 RPC 和 gRPC 服务

`libknock` 可集成到私有 RPC、gRPC 或内部服务间通信路径中。

```text
service A
  -> libknock Dialer
  -> TCP pre-authentication
  -> TLS
  -> gRPC / private RPC
  -> service B
```

它可以与 TLS 或 mTLS 一起使用。TLS 仍提供传输安全和基于证书的认证，而 `libknock` 增加了更早的 TCP 级准入步骤。

## 自定义 TCP 协议

`libknock` 与协议无关，可以保护自定义 TCP 协议、二进制 RPC 协议、设备协议、推送网关、游戏网关或其他长连接 TCP 服务。

```text
net.Listener
  -> libknock.WrapListener()
  -> custom TCP protocol handler
```

```text
libknock Dialer
  -> clean net.Conn
  -> custom TCP protocol starts
```

当应用协议本身不应直接暴露给未认证 TCP 连接时，这很有用。

## 边缘节点和设备网关控制平面

`libknock` 可用于边缘节点、分支节点、工业网关、私有云节点和设备控制平面服务。

```text
edge node
  -> libknock Dialer
  -> TCP pre-authentication
  -> control-plane API
```

在维护场景中，它也可以与可选的 knock 和防火墙 gate 支持组合，创建短生命周期访问窗口。

## 合作伙伴集成端点

对于面向私有合作伙伴的 TCP 服务，`libknock` 可用作 TLS 和应用认证之前的额外准入层。

```text
partner client
  -> TCP pre-authentication
  -> TLS / mTLS
  -> application authentication
  -> business API
```

这不会替代 TLS、mTLS、API token 或业务级授权。它增加了更早的 TCP 级认证步骤。

## 数据库代理或审计网关前端

`libknock` 可集成到自定义数据库代理、SQL 审计网关或数据访问中间件中。

```text
client
  -> libknock Dialer
  -> TCP pre-authentication
  -> database proxy / audit gateway
  -> database
```

这适用于直接集成 SDK 的软件。如果受保护的上游是独立二进制服务，请使用 `relay.Gateway` 或其他网关组件。

## 软件更新、许可证和配置通道

客户端软件、企业 agent 和私有部署产品，可以在连接许可证服务器、更新服务或配置分发端点之前使用 `libknock`。

```text
client
  -> libknock Dialer
  -> TCP pre-authentication
  -> TLS
  -> update / license / configuration API
```

这可以减少到达应用服务的未认证流量，并提供抗重放的客户端准入。

## 临时维护访问

与可选的 knock 和防火墙 gate 支持组合时，`libknock` 可用于临时维护窗口。

```text
operator
  -> knock
  -> temporary firewall allow
  -> TCP pre-authentication
  -> maintenance service
```

这对紧急维护、诊断服务和受控管理访问很有用。

## 应用协议屏蔽

某些服务不需要将其应用协议解析器暴露给任意 TCP 连接。`libknock` 可以在应用开始处理输入前充当一个小型预认证层。

未认证连接可在到达以下组件前被拒绝：

```text
TLS handshake
HTTP parser
gRPC stack
custom binary protocol parser
business authentication logic
```

## 选择集成模式

| 模式 | 需要 SDK 集成 | TCP 预认证 | 需要 Relay | 适用场景 |
|---|---:|---:|---:|---|
| 认证监听器 | 是 | 是 | 否 | Go 应用和自定义服务 |
| 认证拨号器 | 是 | 是 | 否 | Go 客户端和 agent |
| Knock + 防火墙 + 认证 | 是 | 是 | 否 | 同时需要 gate 和预认证的服务 |
| Knock + 仅防火墙 | 可选 | 否 | 否 | 无法发送认证帧的原生服务 |
| Relay 网关 | 否 | 是 | 是 | 独立上游 TCP 服务 |

## 非目标

`libknock` 不是 VPN。

`libknock` 不替代 TLS、mTLS、应用认证、授权、审计或访问控制。

`libknock` 不解析或修改应用协议载荷。

`libknock` 不管理上游应用二进制文件。

`libknock` 只在应用协议启动前认证 TCP 连接，然后向调用方返回一个干净的 `net.Conn`。
