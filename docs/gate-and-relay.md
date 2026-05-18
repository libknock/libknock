# Gate and relay

`libknock` provides two composition styles:

- `gate`: wraps or creates a `net.Listener` for applications that embed the SDK.
- `relay`: runs a TCP forwarding gateway in front of another TCP service.

## Gate modes

```go
type GateMode string

const (
    GateAuthOnly          GateMode = "auth-only"
    GateKnockAuthOnly     GateMode = "knock-auth-only"
    GateKnockFirewallAuth GateMode = "knock-firewall-auth"
    GateKnockFirewallOnly GateMode = "knock-firewall-only"
)
```

| Mode | Listener behavior | Firewall required | TCP auth required |
| --- | --- | ---: | ---: |
| `auth-only` | Wraps the listener with TCP authentication. | No | Yes |
| `knock-auth-only` | Starts a knock listener, records a short-lived knock session, then requires TCP authentication bound to that session. The TCP port remains open at the transport layer. | No | Yes |
| `knock-firewall-auth` | Starts a knock listener, opens firewall access for accepted clients, then requires TCP authentication. | Yes | Yes |
| `knock-firewall-only` | Starts a knock listener, opens firewall access for accepted clients, then accepts the matching TCP connection. | Yes | No |

`knock-auth-only` does not manipulate firewall rules. TCP listener visibility remains unchanged; unauthenticated clients can complete the TCP handshake but cannot reach the application protocol unless both knock and TCP authentication succeed. Use it when firewall control is unavailable or undesirable. `knock-firewall-auth` remains the firewall-backed port gate.

`knock-firewall-auth` and `knock-firewall-only` require a non-noop firewall backend. `auth-only` and `knock-auth-only` may use `firewall.Noop{}`.


## Knock + Auth-only

`knock-auth-only` requires a valid knock before TCP authentication. The server records a short-lived knock session, and the matching TCP auth consumes that session before the application receives a clean `net.Conn`. This mode never calls firewall `Init`, `Allow`, `Revoke`, or `Cleanup`, so it does not require root or `CAP_NET_ADMIN`.

TCP listener visibility remains unchanged. Application protocol admission still requires a valid auth frame; unauthenticated connections are closed/reset or produce no useful application response. Compared with `auth-only`, this adds a knock-session precondition; it does not replace `knock-firewall-auth` when firewall gate rules are required.

## GateConfig

```go
type GateConfig struct {
    Mode                   GateMode
    Listen                 string
    Auth                   auth.ServerConfig
    Listener               netx.ListenerConfig
    Firewall               firewall.Backend
    KnockMethod            string
    KnockListen            string
    KnockPort              int
    KnockClients           []knock.ClientSecret
    KnockTimeWindow        time.Duration
    KnockMaxFrameSize      int
    KnockSequence          knock.SequenceOptions
    KnockNonceTTL          time.Duration
    AllowTTL               time.Duration
    MaxConnectionsPerKnock int
    Events                 observability.GatewayEvents
}
```

Important fields:

- `Mode`: gate mode.
- `Listen`: TCP listen address when using `ListenGate` or `Gate.Listen`.
- `Auth`: server-side TCP auth config.
- `Listener`: queue and worker limits for the authenticated listener.
- `Firewall`: firewall backend for knock/firewall modes.
- `KnockMethod`: one of the supported knock method names.
- `KnockListen`: explicit knock listen address.
- `KnockPort`: knock port used when deriving the default knock listen address.
- `KnockClients`: client IDs and secrets accepted by the knock listener.
- `AllowTTL`: firewall lease duration. Default behavior uses a short lease when not set.
- `MaxConnectionsPerKnock`: accepted TCP connections per knock session.
- `Events`: gateway-level event sink.

## Create a listener with Gate

```go
g, err := gate.New(gate.Config{
    Mode:   gate.AuthOnly,
    Listen: ":9000",
    Auth:   serverAuthConfig,
})
if err != nil {
    return err
}

ln, err := g.Listen(ctx)
if err != nil {
    return err
}
```

## Wrap an existing listener

```go
base, err := net.Listen("tcp", ":9000")
if err != nil {
    return err
}

g, err := gate.New(gateConfig)
if err != nil {
    return err
}

ln, err := g.Wrap(ctx, base)
if err != nil {
    return err
}
```

## Explicit opt-in application config

Applications that expose a config switch should keep the switch in their own configuration layer and call `gate.Listen` or `gate.New(...).Wrap` only when enabled.

```go
ln, err := net.Listen("tcp", app.Listen)
if err != nil {
    return err
}
if app.Libknock.Enabled {
    g, err := gate.New(gateConfig)
    if err != nil {
        return err
    }
    ln, err = g.Wrap(ctx, ln)
    if err != nil {
        return err
    }
}
```

This keeps root-package API small while leaving application startup policy explicit.

## Knock + firewall + auth

Use `GateKnockFirewallAuth` when the server should require a knock session and a TCP auth frame.

```go
g, err := gate.New(gate.Config{
    Mode:        gate.KnockFirewallAuth,
    Listen:      ":9000",
    Auth:        serverAuthConfig,
    Firewall:    fw,
    KnockMethod: "udp",
    KnockPort:   10000,
    KnockClients: []knock.ClientSecret{
        {ClientID: "client-001", Secret: secret},
    },
    AllowTTL:               30 * time.Second,
    MaxConnectionsPerKnock: 1,
})
```

The successful knock creates a short-lived session. The following TCP auth frame must carry the matching client identity and session ID when session binding is enabled by the dialer and knock sender.

## Knock + firewall only

Use `GateKnockFirewallOnly` when the application protocol cannot send a `libknock` TCP auth frame.

```go
g, err := gate.New(gate.Config{
    Mode:        gate.KnockFirewallOnly,
    Listen:      ":9000",
    Firewall:    fw,
    KnockMethod: "udp",
    KnockPort:   10000,
    KnockClients: []knock.ClientSecret{
        {ClientID: "client-001", Secret: secret},
    },
})
```

This mode provides listener admission through knock and firewall only. It does not perform TCP payload authentication.

## Relay gateway

`relay.Gateway` listens on a TCP address and forwards accepted connections to an upstream TCP address.

```go
gw := relay.Gateway{
    Listen:   ":9000",
    Upstream: "127.0.0.1:19000",
    Auth:     serverAuthConfig,
    Firewall: firewall.Noop{},
}

if err := gw.Run(ctx); err != nil {
    return err
}
```

Common fields:

```go
type Gateway struct {
    Listen                 string
    Upstream               string
    Auth                   auth.ServerConfig
    Firewall               firewall.Backend
    KnockMethod            string
    KnockListen            string
    KnockPort              int
    KnockClients           []knock.ClientSecret
    KnockTimeWindow        time.Duration
    KnockMaxFrameSize      int
    KnockSequence          knock.SequenceOptions
    KnockNonceTTL          time.Duration
    AllowTTL               time.Duration
    UpstreamConnectTimeout time.Duration
    IdleTimeout            time.Duration
    RemoveAfterAuth        bool
    MaxConnectionsPerKnock int
    DisableSessionBinding  bool
    MaxPendingAuth         int
    MaxAuthWorkers         int
    Events                 relay.EventSink
}
```

`MaxPendingAuth` and `MaxAuthWorkers` bound concurrent authentication work. `UpstreamConnectTimeout` bounds upstream connection establishment. `IdleTimeout` bounds inactive relayed connections.

## Mode selection

| Scenario | Suggested component |
| --- | --- |
| Application can wrap its own listener | `WrapListener` or `GateAuthOnly` |
| Application wants knock + firewall + TCP authentication | `GateKnockFirewallAuth` |
| Application wants knock + firewall listener admission | `GateKnockFirewallOnly` |
| A separate upstream TCP service should remain behind a forwarding gateway | `relay.Gateway` |

## Lifecycle

For gate and relay modes that manage firewall rules, run them under a context that is cancelled during application shutdown. Call `Gate.Close(ctx)` when the application owns a `Gate` value and needs explicit cleanup.

Use a service manager shutdown hook where available. This is especially important for the plain `iptables` backend because rule expiry depends on process-managed timers and cleanup.

## Knock method boundary

`gate` currently accepts only active UDP listener methods: `udp` and `udp-seq`. It rejects passive capture and TCP SYN-shaped methods because those paths do not expose the same synchronous listener-readiness contract that `gate` requires before returning the protected TCP listener.

`relay` supports the broader server-side method set: `udp`, `udp-seq`, `udp-passive`, `udp-passive-seq`, `tcp-syn`, and `tcp-syn-seq`. Passive and SYN paths remain platform-specific and require the privileges documented in [Knock methods](knock-methods.md) and [Known limitations](known-limitations.md).
