# 入门

本指南展示一个用于自定义 TCP 服务的最小可用 `libknock` 集成，然后将其扩展到 TLS/HTTP、gRPC，以及由配置驱动的嵌入方式。

## 1. 创建共享客户端密钥

使用至少 16 字节的随机密钥。推荐使用 32 字节密钥。

```sh
openssl rand -base64 32
```

应用程序配置可以用应用程序已有的任意格式保存该值。在构建 `libknock.ServerConfig` 或 `libknock.ClientConfig` 之前，将其转换为 `[]byte`。

## 2. 包装 TCP 监听器

```go
secret := []byte("0123456789abcdef0123456789abcdef")

ln, err := net.Listen("tcp", ":9000")
if err != nil {
    return err
}

ln = libknock.WrapListener(ln, libknock.ServerConfig{
    ServerPort: 9000,
    Secrets: libknock.NewStaticSecretResolver(map[string][]byte{
        "client-001": secret,
    }),
    ReplayCache: libknock.NewMemoryReplayCache(5 * time.Minute),
})

for {
    conn, err := ln.Accept()
    if err != nil {
        return err
    }
    go handleConn(conn)
}
```

`WrapListener` 保留常规的 `net.Listener` 形态。`Accept` 返回后，连接已经通过了 `libknock` 认证。

`WrapListener` 和 `NewServer` 可以创建由服务器拥有的重放缓存。如果直接调用低层 `ServerAuth` 函数，请在 `ServerConfig` 中提供共享的 `ReplayCache`。

## 3. 通过 libknock 拨号

```go
d := libknock.Dialer{
    Base: &net.Dialer{Timeout: 5 * time.Second},
    Config: libknock.ClientConfig{
        ClientID:    "client-001",
        Secret:      secret,
        ServerPort:  9000,
        AuthTimeout: 3 * time.Second,
    },
}

conn, err := d.DialContext(ctx, "tcp", "server.example.com:9000")
if err != nil {
    return err
}
```

返回的连接是普通的 `net.Conn`。应用程序可以立即启动自己的协议。

## 4. 认证后使用 TLS 或 HTTP

服务器：

```go
ln, err := net.Listen("tcp", ":443")
if err != nil {
    return err
}

ln = libknock.WrapListener(ln, knockCfg)
tlsLn := tls.NewListener(ln, tlsCfg)

srv := &http.Server{Handler: appHandler}
return srv.Serve(tlsLn)
```

客户端：

```go
transport := &http.Transport{
    DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
        rawConn, err := knockDialer.DialContext(ctx, network, addr)
        if err != nil {
            return nil, err
        }

        tlsConn := tls.Client(rawConn, tlsCfg)
        if err := tlsConn.HandshakeContext(ctx); err != nil {
            rawConn.Close()
            return nil, err
        }
        return tlsConn, nil
    },
}

client := &http.Client{Transport: transport}
```

## 5. 认证后使用 gRPC

```go
ln, err := net.Listen("tcp", ":443")
if err != nil {
    return err
}

ln = libknock.WrapListener(ln, knockCfg)
ln = tls.NewListener(ln, tlsCfg)

grpcServer := grpc.NewServer()
return grpcServer.Serve(ln)
```

## 6. 使用显式选择加入的 gate 接线

当应用有配置开关时，把开关留在应用代码里，只在启用时调用 gate 包。

```go
ln, err := net.Listen("tcp", app.Listen)
if err != nil {
    return err
}
if app.Libknock.Enabled {
    g, err := gate.New(gate.Config{Mode: gate.AuthOnly, Auth: knockCfg})
    if err != nil {
        return err
    }
    ln, err = g.Wrap(ctx, ln)
    if err != nil {
        return err
    }
}
```

根包只保留核心 TCP auth SDK；高级 gate 模式位于 `github.com/libknock/libknock/gate`。

## 7. 从应用程序配置构建 SDK 配置

`libknock` 不读取 YAML、JSON、TOML、环境变量或命令行标志。嵌入应用程序负责配置解析，并将自己的配置映射到类型化的 SDK 结构体。

```go
func buildKnockServerConfig(c AppConfig) libknock.ServerConfig {
    return libknock.ServerConfig{
        ServerPort:  c.PreAuth.ServerPort,
        AuthTimeout: c.PreAuth.AuthTimeout,
        TimeWindow:  c.PreAuth.TimeWindow,
        MaxFrameSize: 1024,
        Secrets:     libknock.NewStaticSecretResolver(c.PreAuth.Clients),
        ReplayCache: libknock.NewMemoryReplayCache(5 * time.Minute),
    }
}
```

应用程序配置形状示例：

```yaml
server:
  listen: ":9000"

preauth:
  enabled: true
  server_port: 9000
  auth_timeout: "3s"
  time_window: "30s"
  clients:
    client-001: "base64-or-raw-secret-from-your-own-config-loader"
```

上面的 YAML 形状只是应用程序示例。它不是 SDK 要求。

## 8. 选择 TCP 认证协议

默认协议是 `tcp-auth-envelope-v2`。

```go
clientCfg.Protocol = auth.AuthProtocolEnvelopeV2
serverCfg.Protocol = auth.AuthProtocolEnvelopeV2
serverCfg.AcceptProtocols = []auth.AuthProtocol{auth.AuthProtocolEnvelopeV2}
```

`tcp-auth-frame-v1` 和 `tcp-auth-envelope-v2` 都是受支持的协议。发布过程中请保持客户端和服务器协议设置一致。

## 9. 需要时添加 knock 和防火墙门控

对于需要在 TCP 认证之前执行 knock 步骤的应用程序：

```go
g, err := gate.New(gate.Config{
    Mode:        gate.KnockFirewallAuth,
    Listen:      ":9000",
    Auth:        knockAuthCfg,
    Firewall:    fw,
    KnockMethod: "udp",
    KnockPort:   10000,
    KnockClients: []knock.ClientSecret{
        {ClientID: "client-001", Secret: secret},
    },
    AllowTTL: 30 * time.Second,
})
if err != nil {
    return err
}

ln, err := g.Listen(ctx)
```

不需要防火墙步骤时，请使用 `auth-only`。
