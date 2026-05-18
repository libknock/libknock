# 可观测性

`libknock` 通过事件接口报告认证、敲门、防火墙和 relay 活动。应用选择如何记录、计数、导出或采样这些事件。

## 认证事件

```go
type EventSink interface {
    OnAccept(remote net.Addr)
    OnAuthOK(peer PeerInfo)
    OnAuthFail(remote net.Addr, reason error)
    OnReplay(remote net.Addr, peerHint uint64)
    OnRateLimited(remote net.Addr)
}
```

将其附加到 `ServerConfig.Events`。

```go
serverCfg.Events = myEventSink
```

## 网关事件

`gate` 和 `relay` 使用来自 `observability` 包的网关级事件类型：

- 敲门已接受
- 敲门失败
- 防火墙允许
- 防火墙错误
- relay 连接已打开
- relay 连接已关闭
- relay 错误

通过 `GateConfig.Events` 或 `relay.Gateway.Events` 附加接收器。

## Prometheus 适配器

Prometheus 适配器位于一个嵌套模块中：

```go
import knockprom "github.com/libknock/libknock/observability/prometheus"
```

示例：

```go
reg := prometheus.NewRegistry()

sink, err := knockprom.New(knockprom.Config{
    Registerer: reg,
})
if err != nil {
    return err
}

serverCfg.Events = sink
gateway.Events = sink
```

单独测试它：

```sh
go -C observability/prometheus test ./...
```

## 标签指南

适配器默认禁用客户端标签。仅当客户端基数受控时，才启用 `IncludeClientLabel`。

对于方法标签，使用包中的方法名称：

```text
tcp-syn
tcp-syn-seq
udp
udp-seq
udp-passive
udp-passive-seq
tcp-auth
unknown
```

如果应用接受用户控制的方法值，请在将其作为标签导出前，把未知值规范化为 `unknown`。

## 日志指南

生产事件接收器应避免记录原始密钥、完整帧字节或 sealed payload 字节。改为记录稳定的运维字段：

- 远端地址
- 成功认证后的客户端 ID
- 方法
- 协议
- 受保护端口
- 原因类别
- 持续时间
- 结果

推荐的失败日志形状：

```json
{
  "component": "libknock",
  "event": "auth_fail",
  "remote": "203.0.113.10:49152",
  "reason": "auth_failed",
  "protocol": "tcp-auth-envelope-v2"
}
```

推荐的成功日志形状：

```json
{
  "component": "libknock",
  "event": "auth_ok",
  "client_id": "client-001",
  "remote": "203.0.113.10:49152",
  "method": "tcp-auth",
  "server_port": 9000,
  "protocol": "tcp-auth-envelope-v2"
}
```

## 指标指南

至少跟踪：

- 认证前接受的 TCP 连接数
- 成功认证计数
- 按原因类别划分的认证失败计数
- 重放计数
- 速率限制计数
- 敲门接受计数
- 按原因类别划分的敲门失败计数
- 防火墙允许错误
- relay 上游错误
- 当前 relay 连接数

除非你的部署有严格边界，否则保持高基数标签禁用。
