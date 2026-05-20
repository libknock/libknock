# Knock method support

Knock methods are optional components used by `gate` and `relay`. They are implemented in the `knock` package and can also be called directly through `knock.SendMethod`.

## Supported methods

| Method | Summary | Client side | Server side |
| --- | --- | --- | --- |
| `tcp-syn` | Single TCP SYN knock. | Linux raw socket, Windows WinDivert/Npcap, macOS raw socket. | Linux raw socket, macOS BPF. |
| `tcp-syn-seq` | Multi-part TCP SYN sequence knock. | Linux raw socket, Windows WinDivert/Npcap, macOS raw socket. | Linux raw socket, macOS BPF. |
| `udp` | Single UDP knock. | Standard UDP socket. | Standard UDP socket. |
| `udp-seq` | Multi-part UDP sequence knock. | Standard UDP socket. | Standard UDP socket. |
| `udp-passive` | UDP knock read by packet capture on the server side. | Standard UDP sender. | Linux AF_PACKET or macOS BPF. |
| `udp-passive-seq` | Multi-part UDP sequence read by packet capture on the server side. | Standard UDP sequence sender. | Linux AF_PACKET or macOS BPF. |

## Method order for configuration UIs

Use this order when presenting method choices:

```text
tcp-syn
tcp-syn-seq
udp
udp-seq
udp-passive
udp-passive-seq
```

## Client dispatch

```go
err := knock.SendMethod(ctx, "udp-seq", knock.SendOptions{
    ServerAddr: "server.example.com:10000",
    ClientID:   "client-001",
    Secret:     secret,
    ServerPort: 9000,
    Sequence: knock.SequenceOptions{
        Length:         3,
        PacketInterval: 80 * time.Millisecond,
    },
})
```

Accepted method aliases:

- `udp-sequence` maps to `udp-seq`.

## UDP methods

`udp` sends one UDP datagram. `udp-seq` sends several UDP datagrams that share a sequence ID. The server completes a sequence only after all parts arrive within the sequence window.

Sequence defaults:

| Field | Default |
| --- | --- |
| `Window` | `5s` |
| `DefaultSequenceMaxParts` | `8` |

Use `udp` when a single authenticated datagram is enough. Use `udp-seq` when the deployment wants multiple short-window datagrams before creating an admission session.

## UDP passive methods

`udp-passive` and `udp-passive-seq` read UDP knock traffic through packet capture on the server side instead of a normal UDP listener. These modes require packet capture privileges on the server platform.

Use passive UDP only when the deployment can provide the required platform capability and firewall configuration. See [Firewall backends](firewall.md) and [Production deployment](production.md) for lifecycle and capability notes.

## TCP SYN methods

`tcp-syn` uses one SYN-shaped knock. `tcp-syn-seq` uses several parts. These methods require raw packet capability on the participating platform paths.

Platform notes:

| Platform | Notes |
| --- | --- |
| Linux | Raw socket capability is required for TCP SYN paths. |
| Windows | WinDivert is preferred for advanced TCP SYN paths; Npcap fallback depends on local installation and privileges. |
| macOS | Raw socket or BPF/pcap capability is required depending on path. |

For short-window reconnect workflows, sequence methods give better operational behavior than a single deterministic knock.

## Session binding

Knock methods can carry a `session_id`. With `GateKnockFirewallAuth` or relay session binding, the following TCP auth frame must carry the matching session ID. This binds the knock event and TCP authentication event to the same short-lived admission record.

`netx.Dialer` can generate a random session ID and pass it to a knock sender that implements the session-bound sender interface.

## Direct package usage

Listener APIs accept typed options:

```go
type ListenOptions struct {
    Port             int
    KnockPort        int
    Clients          []ClientSecret
    TimeWindow       time.Duration
    MaxFrameSize     int
    RequireSessionID bool
    ReplayCache      auth.ReplayCache
    AllowPacket      func(net.IP) bool
    PacketLimiter    PacketLimiter
    InvalidPacket    func(net.IP, string)
    Sequence         SequenceOptions
    NonceTTL         time.Duration
}
```

Sender APIs accept typed options:

```go
type SendOptions struct {
    ServerAddr   string
    ClientID     string
    Secret       []byte
    ServerPort   int
    TimeWindow   time.Duration
    MaxFrameSize int
    Sequence     SequenceOptions
    SessionID    []byte
}
```

## Selection guidance

| Requirement | Recommended method |
| --- | --- |
| Easiest cross-platform setup | `udp` |
| Multi-part UDP admission | `udp-seq` |
| Server-side packet capture path | `udp-passive` or `udp-passive-seq` |
| TCP SYN-shaped knock path | `tcp-syn` |
| Multi-part TCP SYN-shaped admission | `tcp-syn-seq` |

Start with `udp` unless a deployment has a specific reason to use another method. `PacketLimiter` runs before AEAD opening on active UDP listeners; enable a per-source-IP limiter for Internet-facing UDP knock ports to keep floods from forcing candidate-secret work.

## Gate and relay support matrix

| Method | `gate` server path | `relay` server path | Privilege / platform notes |
| --- | --- | --- | --- |
| `udp` | supported | supported | Standard UDP listener. |
| `udp-seq` | supported | supported | Standard UDP listener plus sequence aggregation. |
| `udp-passive` | not supported by `gate` | supported | Packet capture path; requires Linux AF_PACKET or macOS BPF/pcap privileges. |
| `udp-passive-seq` | not supported by `gate` | supported | Packet capture path plus sequence aggregation. |
| `tcp-syn` | not supported by `gate` | supported | Requires raw socket / WinDivert / Npcap / BPF depending on platform. |
| `tcp-syn-seq` | not supported by `gate` | supported | Same platform requirements as `tcp-syn`, plus sequence aggregation. |

`gate` rejects methods that cannot provide synchronous listener readiness. That prevents returning a protected TCP listener before the knock listener has actually bound. Use `relay` for passive capture or TCP SYN-shaped methods, and validate the required platform privileges on the target host.
