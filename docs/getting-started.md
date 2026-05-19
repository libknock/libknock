# Getting started

This guide shows the smallest useful `libknock` integration for a custom TCP service, then expands it to TLS/HTTP, gRPC, and config-driven embedding.

## 1. Create a shared client secret

Use a random secret with at least 16 bytes. A 32-byte secret is recommended.

```sh
openssl rand -base64 32
```

Application config can store the value in any format the application already uses. Convert it to `[]byte` before building `libknock.ServerConfig` or `libknock.ClientConfig`.

## 2. Wrap a TCP listener

```go
secret := []byte("0123456789abcdef0123456789abcdef")

ln, err := net.Listen("tcp", ":9000")
if err != nil {
    return err
}

ln, err = libknock.NewListener(ln, libknock.ServerConfig{
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

`NewListener` returns startup validation errors directly and preserves the usual `net.Listener` shape. After `Accept` returns, the connection has already passed `libknock` authentication.

`NewListener`, `WrapListener`, and `NewServer` can create a server-owned replay cache. If you call the low-level `ServerAuth` function directly, provide a shared `ReplayCache` in `ServerConfig`.

## 3. Dial through libknock

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

The returned connection is a normal `net.Conn`. The application can immediately start its own protocol.

## 4. Use TLS or HTTP after authentication

Server:

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

Client:

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

## 5. Use gRPC after authentication

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

## 6. Use explicit opt-in gate wiring

When an application has a config switch, keep the switch in application code and call the gate package only when enabled.

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

The root package remains focused on the core TCP auth SDK; advanced gate modes live in `github.com/libknock/libknock/gate`.

## 7. Build SDK config from application config

`libknock` does not read YAML, JSON, TOML, environment variables, or command-line flags. The embedding application owns configuration parsing and maps its config into typed SDK structs.

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

Example application config shape:

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

The YAML shape above is only an application example. It is not an SDK requirement.

## 8. Select a TCP authentication protocol

The default protocol is `tcp-auth-envelope-v2`.

```go
clientCfg.Protocol = auth.AuthProtocolEnvelopeV2
serverCfg.Protocol = auth.AuthProtocolEnvelopeV2
serverCfg.AcceptProtocols = []auth.AuthProtocol{auth.AuthProtocolEnvelopeV2}
```

`tcp-auth-frame-v1` and `tcp-auth-envelope-v2` are both supported protocols. Keep client and server protocol settings aligned during rollout.

## 9. Add knock and firewall gate when needed

For applications that need a knock step before TCP authentication:

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

Use `auth-only` when no firewall step is required.
