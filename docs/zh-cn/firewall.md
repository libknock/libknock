# 防火墙后端

防火墙后端是可选组件。它们由 `gate` 和 `relay` 的敲门/防火墙模式使用，为受保护的 TCP 端口创建短生命周期的源 IP 访问规则。

## 后端接口

```go
type Backend interface {
    Name() string
    Init(ctx context.Context) error
    Allow(ctx context.Context, remote netip.Addr, port int, ttl time.Duration) error
    Revoke(ctx context.Context, remote netip.Addr, port int) error
    IsAllowed(ctx context.Context, remote netip.Addr, port int) (bool, error)
    Cleanup(ctx context.Context) error
}
```

## 内置后端

| 后端 | 摘要 | 超时行为 |
| --- | --- | --- |
| `noop` | 用于仅认证工作流和测试的内存空操作后端。 | 无系统规则。 |
| `nftables` | 使用 `family inet` 的 Linux nftables 后端。 | 原生面向超时的集合。 |
| `ipset-iptables` | Linux ipset 加 iptables 后端。 | 面向超时的 ipset 条目。 |
| `iptables` | Linux iptables 后端。 | 由进程管理撤销和清理。 |
| `script` | 调用用于允许、撤销和清理的可执行路径。 | 由脚本定义。 |
| `auto` | 根据后端检测选择可用的 Linux 后端。 | 取决于检测到的后端。 |

## 后端选择

推荐的生产顺序：

```text
nftables
ipset-iptables
iptables
script
```

仅在只需要认证的工作流、测试和本地开发中使用 `noop`。

`auto` 按以下顺序检测 Linux 后端：

```text
nftables -> ipset-iptables -> iptables -> script when configured
```

## 端口绑定

安装系统规则的防火墙后端会绑定到一个受保护端口。使用 `firewall.Config.Port` 构造它们，或者让 `gate` / `relay.Gateway` 注入实际的监听/认证端口。

```go
fw, err := firewall.New(firewall.Config{
    Backend: "nftables",
    Port:    9000,
})
```

`Allow`、`Revoke` 和 `IsAllowed` 会在适用时校验同一个受保护端口。

## nftables

nftables 后端使用保守的对象名称和 `family inet`。集合使用显式的超时标志。请将配置的表、链和集合名称专用于 `libknock`，因为清理流程会拥有这些对象。

```go
fw, err := firewall.New(firewall.Config{
    Backend: "nftables",
    Port:    9000,
    Nftables: firewall.NftablesConfig{
        Table:  "libknock",
        Chain:  "input",
        SetV4:  "allowed_clients_v4",
        SetV6:  "allowed_clients_v6",
        Family: "inet",
    },
})
```

## ipset-iptables

ipset-iptables 后端将允许的客户端存储在 ipset 集合中，并使用 iptables 规则引用这些集合。对于已经标准化使用 ipset 的部署，它很合适。

```go
fw, err := firewall.New(firewall.Config{
    Backend: "ipset-iptables",
    Port:    9000,
    IPSet: firewall.IPSetConfig{
        Set:   "libknock_allowed_v4",
        SetV6: "libknock_allowed_v6",
    },
    Iptables: firewall.IptablesConfig{
        Chain: "LIBKNOCK",
    },
})
```

## iptables

iptables 后端安装按客户端划分的 ACCEPT 规则，并在撤销或清理期间清除它们。传给 `Allow` 的 `ttl` 由 gate/relay 计时器强制执行，计时器随后会调用 `Revoke`；iptables 规则本身不携带超时。

如果宿主进程意外退出，ACCEPT 规则可能会一直保留，直到下一次 `Init`/`Cleanup` 流程移除由 `libknock` 管理的规则。对于需要内核强制过期的生产部署，优先使用 `nftables` 或 `ipset-iptables`。

为受保护服务使用专用链名。

```go
fw, err := firewall.New(firewall.Config{
    Backend: "iptables",
    Port:    9000,
    Iptables: firewall.IptablesConfig{
        Chain: "LIBKNOCK",
    },
})
```

## script 后端

script 后端直接调用可执行路径。它不会运行 shell 命令字符串。

```text
allow_cmd <remote_ip> <port> <ttl_seconds>
revoke_cmd <remote_ip> <port>
cleanup_cmd <port>
```

在脚本中，将参数视为数据。将位置参数引用为 `"$1"`、`"$2"` 和 `"$3"`；不要对它们执行 `eval`，也不要将它们拼接进 shell 命令字符串。

安全的 shell 模板：

```sh
#!/bin/sh
set -eu
remote_addr="$1"
port="$2"
ttl_seconds="${3:-}"
iptables -I LIBKNOCK 1 -s "$remote_addr" -p tcp --dport "$port" -j ACCEPT
```

示例：

```go
fw, err := firewall.New(firewall.Config{
    Backend: "script",
    Port:    9000,
    Script: firewall.ScriptConfig{
        AllowCmd:   "/usr/local/libknock/allow",
        RevokeCmd:  "/usr/local/libknock/revoke",
        CleanupCmd: "/usr/local/libknock/cleanup",
    },
})
```

script 后端不管理 `DropUDPKnockPort`；当需要该选项时，请使用 `nftables`、`iptables` 或 `ipset-iptables`。

## drop_udp_knock_port

`DropUDPKnockPort` 用于 UDP 被动模式。它要求防火墙后端在服务器通过包捕获读取数据包时，管理 UDP 敲门端口的 DROP 行为。

规则：

- 仅与 `udp-passive` 或 `udp-passive-seq` 一起使用。
- 使用支持该操作的后端。
- 在真实环境中验证生成的防火墙规则。

## Gate 和 relay 集成

`GateKnockFirewallAuth`、`GateKnockFirewallOnly` 以及 relay 的敲门/防火墙工作流需要真实的防火墙后端。`GateAuthOnly` 和 relay 的仅认证工作流可以使用 `firewall.Noop{}`。

## 清理

在受控关闭期间调用 `Cleanup`。`gate` 和 `relay.Gateway` 会为其托管的监听器将清理连接到上下文取消。对于系统防火墙后端，请在宿主进程或服务管理器中将服务生命周期与关闭钩子配对。

对于普通的 `iptables` 后端，清理尤其重要，因为规则过期由进程管理，而不是由内核管理。

## 能力检查

在启用生产防火墙后端之前，使用 `firewall.Probe` 或应用专用诊断：

```go
res, err := firewall.Probe(ctx, firewall.Config{
    Backend: "nftables",
    Port:    9000,
})
```

在打开监听器之前，检查命令可用性、有效用户权限以及后端特定错误。
