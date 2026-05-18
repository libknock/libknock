# libknock 文档

本目录包含关于嵌入、运行、测试和扩展 `libknock` 的详细文档。

## 指南

- [入门](getting-started.md)：第一个服务器/客户端集成、配置映射，以及 TLS/HTTP/gRPC 组合。
- [使用场景](use-cases.md)：管理端点、代理、RPC、自定义 TCP 服务和中继网关的典型集成场景。
- [API 参考](api.md)：公共类型、函数、配置结构体和扩展接口。
- [协议](protocols.md)：TCP 认证协议 v1、TCP 认证协议 v2、UDP knock 帧、会话和服务器证明。
- [门控与中继](gate-and-relay.md)：监听器门控模式和中继网关组合。
- [Knock 方法](knock-methods.md)：支持的 knock 方法、平台说明和方法选择。
- [防火墙后端](firewall.md)：后端模型、端口绑定、清理和后端选择。
- [可观测性](observability.md)：事件接收器、Prometheus 适配器，以及标签/基数指导。
- [生产部署](production.md)：运行默认值、后端选择、生命周期和平台说明。
- [故障排查](troubleshooting.md)：常见的集成和部署失败。
- [发布检查清单](release-checklist.md)：RC 和稳定版发布前的可重复检查。
- [验证模板](validation-template.md)：真实主机验证证据模板。
- [模式](modes.md)：gate 模式语义和端口可见性。
- [防火墙部署](deployment-firewall.md)：后端选择和 fallback 风险。
- [平台支持](platform-support.md)：stable、experimental、compile-only 和 not supported 平台路径。
- [验证矩阵](validation-matrix.md)：按区域记录 unit / integration / dry-run / hardware 状态。
- [已知限制](known-limitations.md)：验证边界和未实机验证区域。
- [开发指南](development.md)：仓库布局、测试矩阵、发布检查和扩展规则。

## 设计摘要

`libknock` 工作在 TCP 连接边界。SDK 认证自己的二进制帧，并向调用方返回干净的 `net.Conn`。嵌入它的应用程序仍负责配置、生命周期、协议处理器、TLS 设置、日志策略、部署和业务授权。

核心 API 有意保持很小：

```go
ln = libknock.WrapListener(ln, serverConfig)
server, err := libknock.NewServer(serverConfig)
conn, peer, err := server.Auth(ctx, conn)
conn, peer, err := libknock.ServerAuth(ctx, conn, serverConfig)
err = libknock.ClientAuth(ctx, conn, clientConfig)
conn, err = (&libknock.Dialer{Base: baseDialer, Config: clientConfig}).DialContext(ctx, network, address)
```

常规服务器集成请使用 `WrapListener` 或 `NewServer`。仅当嵌入应用程序已经自行拥有连接接受流程和重放缓存生命周期时，才直接使用 `ServerAuth`。

## 推荐阅读顺序

对于应用程序集成，请阅读：

1. [入门](getting-started.md)
2. [API 参考](api.md)
3. [生产部署](production.md)

对于网关式部署，请阅读：

1. [门控与中继](gate-and-relay.md)
2. [Knock 方法](knock-methods.md)
3. [防火墙后端](firewall.md)

对于发布或贡献工作，请阅读：

1. [协议](protocols.md)
2. [发布检查清单](release-checklist.md)
3. [开发指南](development.md)
