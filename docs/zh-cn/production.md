# 生产部署

本文档总结面向生产环境的默认值、后端选择、生命周期处理和平台注意事项。

## 推荐默认值

| 设置 | 推荐值 |
| --- | --- |
| TCP 认证协议 | `tcp-auth-envelope-v2` |
| `AuthTimeout` | `3s` |
| `TimeWindow` | `30s` |
| `ReplayCache` TTL | 至少为 `TimeWindow * 2` |
| `MaxFrameSize` | `1024`，除非部署需要更小的上限 |
| `MaxAuthAttempts` | 默认 `64` |
| 密钥长度 | 推荐 32 个随机字节；最低 16 字节 |
| envelope v2 提示模式 | `route-hint` |
| envelope v2 填充 | `random-bucket` |
| 服务端证明 | 除非特别需要，否则禁用 |

## 密钥处理

使用随机密钥，并避免将其写入日志。

```sh
openssl rand -base64 32
```

轮换选项：

- 使用 `NewRotatingSecretResolver` 为同一客户端接受多个密钥版本。
- 先将新密钥部署到客户端。
- 将服务端配置为在轮换窗口内同时接受旧密钥和新密钥。
- 所有客户端切换后移除旧密钥。

## 重放缓存生命周期

每个逻辑服务端实例使用一个重放缓存。

推荐模式：

- `WrapListener`：未提供时使用监听器拥有的重放缓存。
- `NewServer`：未提供时使用服务端拥有的重放缓存。
- `ServerAuth`：调用方必须提供共享的 `ReplayCache`。

不要为每个连接创建新的重放缓存。

## 防火墙后端选择

推荐顺序：

```text
nftables
ipset-iptables
iptables
script
```

仅在纯认证工作流和测试中使用 `noop`。

后端说明：

| 后端 | 生产说明 |
| --- | --- |
| `nftables` | 可用时首选的 Linux 后端。 |
| `ipset-iptables` | 适合基于 ipset 的环境。 |
| `iptables` | 可作为回退方案，但规则过期由进程管理。 |
| `script` | 当应用必须调用站点特定的防火墙工具时使用。 |

普通 `iptables` 后端依赖撤销/清理定时器。不干净的进程退出可能会留下临时规则，直到下一次清理流程。需要内核强制过期时，优先使用 `nftables` 或 `ipset-iptables`。

## 服务生命周期

对于会管理防火墙规则的 gate 或 relay 工作流：

1. 在接受流量前初始化防火墙后端。
2. 在可取消的 context 下运行 gate/relay。
3. 服务关闭时取消 context。
4. 使用有界超时调用清理。
5. 在部署环境中验证清理行为。

示例关闭模式：

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

errCh := make(chan error, 1)
go func() { errCh <- gw.Run(ctx) }()

// On application shutdown:
cancel()
select {
case err := <-errCh:
    return err
case <-time.After(5 * time.Second):
    return context.DeadlineExceeded
}
```

## Linux 注意事项

验证：

- 命令可用性：按需检查 `nft`、`iptables`、`ipset`
- 用于防火墙变更的有效权限
- 受保护端口绑定
- IPv4 和 IPv6 行为
- 清理幂等性
- 不干净关闭后的启动清理
- 使用被动 UDP 方法时的 UDP 被动包捕获权限

对于包捕获路径，检查平台所需的 `CAP_NET_RAW` 或等效权限。

## Windows 注意事项

普通 UDP 发送器路径是最简单的 Windows 客户端路径。

TCP SYN knock 路径需要额外的数据包工具，例如 WinDivert 或 Npcap，具体取决于代码路径和部署。在启用这些模式之前，为你的产品记录安装程序要求和管理员权限要求。

在精确部署环境中完成验证前，将 Windows 支持视为平台特定支持。

## macOS 注意事项

UDP 发送器路径较直接。被动捕获和 TCP SYN 路径需要平台包能力，例如 BPF/pcap 或原始套接字权限。

在目标 OS 版本上验证前，将 macOS 包捕获模式视为平台特定支持。

## 协议 rollout

默认 TCP 认证协议是 `tcp-auth-envelope-v2`。

对于受控 rollout：

1. 为新客户端选择协议。
2. 使用预期的 `AcceptProtocols` 集配置服务端。
3. 在 CI 中测试每个被接受的协议路径。
4. 保持混合协议窗口短且明确。
5. rollout 完成后移除未使用的已接受协议。

## 容量控制

对公共监听器使用这些控制项：

- `AuthTimeout`
- `MaxFrameSize`
- `MaxAuthAttempts`
- `netx.ListenerConfig.MaxPendingAuth`
- `netx.ListenerConfig.MaxAuthWorkers`
- `Policy` hook
- relay `MaxPendingAuth`
- relay `MaxAuthWorkers`
- 应用级连接限制

## 日志策略

不要记录：

- 原始共享密钥
- 完整认证帧
- 密封载荷字节
- 完整 knock 数据报

优先使用带原因类别、且不含原始数据包内容的结构化日志。

## 最低发布门槛

稳定发布前，运行：

```sh
go test ./...
go vet ./...
go test -race ./auth ./firewall ./knock ./netx ./policy ./protocol ./relay
go -C observability/prometheus test ./...
go -C test/integration/grpc test ./...
```

然后完成 [发布检查清单](release-checklist.md) 中的环境检查。
