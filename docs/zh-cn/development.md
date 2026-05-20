# 开发指南

本指南说明 `libknock` 贡献者需要了解的内部包布局、测试工作流和扩展规则。

## 仓库布局

```text
protocol/       TCP auth and UDP knock wire formats, codec, crypto helpers
auth/           server/client auth state machines, replay cache, secret resolvers
netx/           authenticated listener and dialer wrappers
gate/           SDK listener composition modes
relay/          TCP relay gateway and knock session store
knock/          knock senders, listeners, sequence tracking
firewall/       firewall backend interface and implementations
policy/         limiter and ban policy adapters
observability/  event interfaces and optional metrics adapters
cmd/knock-proxy command entrypoint
examples/       runnable integration examples
```

## 包边界

`protocol` 负责字节级格式。它应保持不包含网络监听器逻辑。

`auth` 负责认证状态机。它可以依赖 `protocol`、重放缓存、密钥解析器和事件接口。

`netx` 负责 `net.Listener` 和 `net.Dialer` 集成。

`gate` 为嵌入 SDK 的应用组合监听器、knock、防火墙和认证行为。

`relay` 组合认证、可选的 knock/防火墙以及 TCP 转发。

`knock` 负责 knock 数据包发送/监听行为和序列聚合。

`firewall` 负责防火墙后端和命令执行边界。

`cmd/knock-proxy` 将产品配置接入 SDK 结构体和命令行为。

## 核心不变式

保持以下不变式稳定：

1. 服务端认证成功后返回一个干净的 `net.Conn`。
2. 读取到认证帧之外的字节，仍会通过带缓冲的连接处理保留给应用协议。
3. 重放保护的作用域限定在一个逻辑服务端生命周期内。
4. 公共输入路径会强制执行明确的大小限制。
5. 安装系统规则的防火墙后端绑定到一个受保护端口。
6. SDK 包接受类型化的 Go 值和接口。
7. 可选适配器保持在核心依赖路径之外。
8. 公共网络失败行为不会暴露详细的认证原因。
9. SDK 代码不会记录密钥、原始帧和密封载荷字节。

## 测试工作流

核心模块：

```sh
go test ./...
go vet ./...
go build ./...
go test -race ./auth ./firewall ./gate ./knock ./netx ./policy ./protocol ./relay
```

Prometheus 模块：

```sh
go -C observability/prometheus test ./...
go -C observability/prometheus vet ./...
```

gRPC 集成模块：

```sh
go -C test/integration/grpc test ./...
go -C test/integration/grpc vet ./...
```

短时 fuzz 检查：

```sh
go test ./protocol -run=^$ -fuzz=FuzzDecodePayload -fuzztime=30s
go test ./protocol -run=^$ -fuzz=FuzzReadFrame -fuzztime=30s
go test ./auth -run=^$ -fuzz=FuzzServerAuthMalformedInput -fuzztime=30s
```

跨平台构建矩阵：

```sh
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  GOOS=${target%/*} GOARCH=${target#*/} go build ./...
done
```

## 示例

示例应保持在最少配置下可运行：

```text
examples/custom-binary-protocol/
examples/http-client/
examples/tls-client/
examples/tls-server/
examples/grpc-client/
examples/grpc-server/
```

让示例代码一次只聚焦一种集成模式。

## 添加协议字段

添加经过认证的元数据时：

1. 在 `protocol` 中定义字节级表示。
2. 添加编码/解码往返测试。
3. 添加畸形输入测试。
4. 根据字段语义，将字段绑定到 AEAD 载荷或 AAD。
5. 添加服务端校验。
6. 添加客户端构造。
7. 仅当应用需要观察该字段时更新 `PeerInfo`。
8. 更新文档和示例。

## 添加 knock 方法

添加 knock 方法时：

1. 在 `knock` 中添加方法常量和发送器/监听器实现。
2. 在 `SendMethod` 中添加客户端分发。
3. 按需添加特定平台的构建标签。
4. 添加 `gate` 和 `relay` 所需的事件字段。
5. 添加重放和序列测试。
6. 更新 [Knock 方法](knock-methods.md)。

在文档和 UI 中使用以下显示顺序：

```text
tcp-syn
tcp-syn-seq
udp
udp-seq
udp-passive
udp-passive-seq
```

## 添加防火墙后端

添加防火墙后端时：

1. 实现 `firewall.Backend` 接口。
2. 校验受保护端口绑定。
3. 在特权操作前校验命令/对象名称。
4. 在可行情况下，使 `Init`、`Allow`、`Revoke`、`IsAllowed` 和 `Cleanup` 具备幂等性。
5. 在适用时添加 dry-run 或 fake-runner 测试。
6. 在发布检查中添加真实环境测试说明。
7. 更新 [防火墙后端](firewall.md)。

## 更新公共 API

更改公共 API 前：

1. 在 API 应从 `github.com/libknock/libknock` 暴露时更新根别名。
2. 在可行时通过根包添加测试。
3. 更新 [API 参考](api.md)。
4. 如果变更影响常见集成路径，请更新示例。
5. 将可选适配器保持在核心依赖路径之外。

## 发布检查

标记候选版本前：

```sh
git ls-files '*.go' ':!:vendor/**' | xargs gofmt -l
go test ./...
go vet ./...
go build ./...
go test -race ./auth ./firewall ./gate ./knock ./netx ./policy ./protocol ./relay
go -C observability/prometheus test ./...
go -C test/integration/grpc test ./...
```

稳定标签前建议执行的环境检查：

```text
Linux nftables backend
Linux ipset-iptables backend
Linux iptables backend
UDP sequence methods
UDP passive methods
TCP SYN sequence methods on available platforms
Prometheus adapter module
Example programs
```

以 [发布检查清单](release-checklist.md) 作为权威发布检查清单。
