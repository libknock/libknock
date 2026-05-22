# 协议

`libknock` 有三个线路级组件：

1. TCP 认证协议 v1：`tcp-auth-frame-v1`
2. TCP 认证协议 v2：`tcp-auth-envelope-v2`
3. UDP knock 帧 v1

三者都使用已认证的加密成帧和有界输入大小。默认 AEAD 是 XChaCha20-Poly1305。HKDF-SHA256 用于帧特定的密钥派生。

## TCP 认证协议 v1

`tcp-auth-frame-v1` 是一个紧凑的二进制帧，在 TCP 连接之后、应用协议开始之前立即使用。

```text
fixed header:
  version[1]
  flags[1]
  reserved[1]
  nonce[16]
  key_hint[8]
  sealed_len[2]

sealed payload:
  AEAD(client_id_hash, timestamp_unix_ms, server_port, method, session_id, extensions)

AAD:
  version || flags || reserved || nonce || key_hint || sealed_len
```

属性：

- `nonce` 在每次认证尝试中都是随机的。
- `key_hint` 帮助服务器选择候选密钥。
- `sealed_len` 受 `MaxFrameSize` 限制。
- `reserved` 必须为零。
- 未知 TCP 标志会被拒绝。
- 当前有效的 TCP 标志是 `FlagServerProof`。

客户端身份由密封载荷内的 `client_id_hash` 表示。服务器会将已验证的哈希映射回解析出的客户端身份。

## TCP 认证协议 v2

`tcp-auth-envelope-v2` 是一种密封 envelope 格式，在 TCP 连接之后、应用协议开始之前立即使用。

```text
wire:
  prefix_random[24]
  route_hint[0 or 8]
  sealed_envelope[remaining bucket bytes]

bucket_size:
  one of 128, 192, 256, 384, 512 by default

sealed_envelope:
  AEAD(version, flags, timestamp_unix_ms, client_id_hash, server_port,
       method, session_id, extensions, padding_len, random_padding)
```

路由提示：

```text
route_hint = Trunc64(HMAC(client_secret,
  "libknock tcp-auth hint v2" || prefix_random || server_port))
```

密钥派生：

```text
K_auth = HKDF-SHA256(
  secret = client_secret,
  salt   = prefix_random,
  info   = "libknock tcp-auth envelope v2"
)
```

带路由提示的 AAD：

```text
prefix_random || route_hint || bucket_size || server_port || "tcp-auth-envelope-v2"
```

不带路由提示的 AAD：

```text
prefix_random || bucket_size || server_port || "tcp-auth-envelope-v2"
```

启用路由提示时，服务器会用它选择候选密钥，使用 AEAD 打开 envelope，校验时间戳和重放状态，然后向调用方返回干净的 `net.Conn`。路由提示是默认且推荐的模式。`HintModeNone` 会迫使解析器返回更宽泛的候选集合，仅适用于小规模客户端群体或会自行施加限制的自定义解析器。`ServerConfig.MaxAuthAttempts` 限制每个连接的 envelope v2 AEAD 打开尝试次数。

## 协议选择

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

如果 `AcceptProtocols` 包含两个值，监听器可以同时接受两种 TCP 认证协议：

```go
serverCfg.AcceptProtocols = []auth.AuthProtocol{
    auth.AuthProtocolFrameV1,
    auth.AuthProtocolEnvelopeV2,
}
```

发布期间请保持客户端和服务器协议设置一致，并在 CI 中测试每条被接受的协议路径。

## UDP knock 帧 v1

UDP knock 使用数据报大小的二进制帧。

```text
fixed header:
  nonce[16]
  key_hint[8]
  sealed_len[2]
  flags[1]
  reserved[1]

sealed payload:
  AEAD(frame_type, client_id_hash, timestamp_unix_ms, method, server_port,
       session_id, sequence_id, sequence_index, sequence_total,
       client_random, extensions)

AAD:
  nonce || key_hint || sealed_len || flags || reserved || protocol_version || dst_port
```

路由键：

```text
key_hint = Trunc64(HMAC(client_secret,
  "libknock udp-knock hint v1" || nonce || server_port))
```

身份哈希：

```text
client_id_hash = Trunc128(HMAC(client_secret,
  "libknock client-id v1" || client_id))
```

密钥派生：

```text
K_knock = HKDF-SHA256(
  secret = client_secret,
  salt   = nonce,
  info   = "libknock udp-knock frame v1"
)
```

该帧支持单包方法和序列方法。序列字段会在密封载荷中携带。

## 会话

knock 可以携带随机的 `session_id`。启用 `RequireKnock` 时，服务器会记录包含以下内容的会话：

- 远程地址
- 客户端身份
- 受保护端口
- 过期时间
- 剩余使用次数
- 会话 ID

后续 TCP 认证帧必须携带匹配的 `session_id`。一次成功的 TCP 认证会消耗一次使用次数。`RemoveAfterAuth` 可以在认证后立即撤销防火墙租约并清除已存储的会话。

## 服务器证明

服务器证明是可选的。启用后，服务器会在验证客户端认证帧之后返回已认证的证明。客户端设置 `RequireServerProof`，以要求在启动应用协议之前收到该响应。

服务器证明会在应用协议开始前增加一个响应步骤。如果应用程序已经使用带服务器认证的 TLS，请保持禁用，除非部署明确需要额外检查。

## 默认值

| Setting | Default |
| --- | --- |
| TCP auth protocol | `tcp-auth-envelope-v2` |
| `AuthTimeout` | `3s` |
| `TimeWindow` | `30s` |
| `MaxFrameSize` | `1024` |
| `MaxAuthAttempts` | `64` |
| envelope v2 hint mode | `route-hint` |
| envelope v2 padding policy | `random-bucket` |
| envelope v2 buckets | `128`, `192`, `256`, `384`, `512` |
| UDP sequence window | `5s` |
| UDP sequence max parts | `8` |
| minimum secret size | `16` bytes |

## 失败行为

认证失败时，公开网络行为会刻意保持简单：关闭连接。应用程序可以在内部通过 `EventSink` 和普通 Go 错误观察结构化错误类别。

不要将原始密钥、完整帧字节或密封载荷字节写入日志。
