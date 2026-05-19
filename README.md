# libknock

[![License: BSL-1.1](https://img.shields.io/badge/license-BSL--1.1-blue.svg)](LICENSE)
[![Future License: Apache-2.0](https://img.shields.io/badge/future%20license-Apache--2.0-lightgrey.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/libknock/libknock.svg)](https://pkg.go.dev/github.com/libknock/libknock)

Source-available under BSL-1.1. Production use is allowed, but offering libknock or derivative works as a hosted or managed service is restricted before it converts to Apache-2.0 on 2030-05-15. See [LICENSE](LICENSE) and [license notes](docs/license.md).

Embeddable TCP pre-application authentication SDK for Go applications.

It authenticates a compact binary frame after a TCP connection is established and before the application protocol starts. After authentication succeeds, the caller receives a normal `net.Conn` and continues with its own protocol stack: plain TCP, TLS, HTTP, gRPC, custom RPC, agent connections, game protocols, database-like protocols, or any protocol built on top of `net.Conn`.

`libknock` does not parse, modify, or own application payloads. It only performs an admission step at the TCP connection boundary and then hands a clean connection back to the embedding application.


## Dependency model

libknock uses Go modules as the primary dependency path. The main release archive intentionally does not include `vendor/`; builds from a source zip need network access, a populated local module cache, or an internal dependency mirror. Keep `go.work` and `go.work.sum`: they describe the multi-module workspace and are not vendored dependency source.

## What it provides

- Authenticated `net.Listener` wrappers for server-side TCP services.
- Authenticated `net.Dialer` wrappers for clients.
- Standalone `ServerAuth` and `ClientAuth` functions for custom connection pipelines.
- Core root-package SDK entry points for TCP authentication.
- Optional knock, firewall, gate, and relay packages for advanced admission paths.
- Replay protection, timestamp validation, peer metadata, event hooks, and policy hooks.
- Optional Prometheus adapter in a separate module.

## Install

```sh
go get github.com/libknock/libknock
```

## Minimal server

```go
package main

import (
    "log"
    "net"
    "time"

    libknock "github.com/libknock/libknock"
)

func main() {
    secret := []byte("0123456789abcdef0123456789abcdef")

    ln, err := net.Listen("tcp", ":9000")
    if err != nil {
        log.Fatal(err)
    }

    ln, err = libknock.NewListener(ln, libknock.ServerConfig{
        ServerPort: 9000,
        Secrets: libknock.NewStaticSecretResolver(map[string][]byte{
            "client-001": secret,
        }),
        ReplayCache: libknock.NewMemoryReplayCache(5 * time.Minute),
    })
    if err != nil {
        log.Fatal(err)
    }

    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Fatal(err)
        }
        go handleConn(conn)
    }
}
```

`NewListener` returns startup validation errors directly and creates a listener-owned replay cache when one is not provided. `WrapListener` remains available as a convenience `net.Listener` wrapper; configuration errors surface from `Accept`. If you call the low-level `ServerAuth` function directly, provide a shared `ReplayCache` yourself.

## Minimal client

```go
package main

import (
    "context"
    "net"
    "time"

    libknock "github.com/libknock/libknock"
)

func dial(ctx context.Context) (net.Conn, error) {
    secret := []byte("0123456789abcdef0123456789abcdef")

    d := libknock.Dialer{
        Base: &net.Dialer{Timeout: 5 * time.Second},
        Config: libknock.ClientConfig{
            ClientID:    "client-001",
            Secret:      secret,
            ServerPort:  9000,
            AuthTimeout: 3 * time.Second,
        },
    }

    return d.DialContext(ctx, "tcp", "127.0.0.1:9000")
}
```

## Root package and advanced packages

The root package intentionally stays small. It exposes the common SDK path: `NewListener`, `WrapListener`, `WrapListenerE`, `ServerAuth`, `ClientAuth`, `Dialer`, `ServerConfig`, `ClientConfig`, `PeerInfo`, `NewServer`, `NewMemoryReplayCache`, and `NewStaticSecretResolver`.

Advanced admission features live in subpackages. Use `auth` for protocol selectors and advanced auth hooks, `gate` for listener composition modes, `relay` for proxy-style gateways, `firewall` for platform backends, `knock` for knock senders/listeners, and `observability` for gateway events.

```go
import (
    libknock "github.com/libknock/libknock"
    "github.com/libknock/libknock/gate"
)

ln, err := gate.Listen(ctx, gate.Config{
    Mode: gate.AuthOnly,
    Auth: libknock.ServerConfig{
        ServerPort: 9000,
        Secrets: libknock.NewStaticSecretResolver(map[string][]byte{"client-001": secret}),
    },
})
```

## TCP authentication protocols

`libknock` supports two TCP pre-application authentication protocols:

| Protocol | Name | Summary |
| --- | --- | --- |
| v1 | `tcp-auth-frame-v1` | Fixed binary frame with AEAD-sealed authentication metadata. |
| v2 | `tcp-auth-envelope-v2` | Sealed envelope with route hint support and fixed-size bucket padding. |

Both protocols provide client secret validation, timestamp window validation, replay protection, optional knock session binding, peer metadata, event hooks, and optional server proof.

Clients select a protocol with `ClientConfig.Protocol`. Servers select a preferred protocol with `ServerConfig.Protocol` and accepted protocols with `ServerConfig.AcceptProtocols`. The default TCP authentication protocol is `tcp-auth-envelope-v2`.

## UDP knock frame

UDP knock uses a binary datagram frame with an AEAD-sealed payload. The same UDP frame family is used by:

- `udp`
- `udp-seq`
- `udp-passive`
- `udp-passive-seq`

The frame carries authenticated metadata such as client identity hash, method, timestamp, protected port, optional session ID, sequence fields, and extensions.

## Knock method support

| Method | Summary | Typical requirements |
| --- | --- | --- |
| `tcp-syn` | Single TCP SYN knock. | Raw packet capability on sender/listener platforms. |
| `tcp-syn-seq` | Multi-part TCP SYN sequence knock. | Raw packet capability; useful when multiple short-window attempts are needed. |
| `udp` | Single UDP knock over a normal UDP socket. | Standard UDP socket. |
| `udp-seq` | Multi-part UDP sequence knock. | Standard UDP socket. |
| `udp-passive` | UDP knock read through packet capture on the server side. | Packet capture privileges on the server platform. |
| `udp-passive-seq` | Multi-part UDP sequence read through packet capture on the server side. | Packet capture privileges on the server platform. |

For most deployments, start with UDP knock before considering passive or raw-packet methods.

## Capability status

| Capability | Status |
| --- | --- |
| Authenticated listener | stable |
| Dialer | stable |
| TCP auth frame v1 | stable |
| TCP auth envelope v2 | release candidate |
| UDP knock / UDP sequence | release candidate |
| Knock-auth-only gate | release candidate |
| Firewall-backed gates | platform-specific / not fully validated |
| UDP passive knock | experimental / not fully validated |
| TCP SYN knock | experimental / not fully validated |
| Windows packet capture integrations | experimental / not fully validated |
| macOS passive capture integrations | experimental / not fully validated |

## Gate modes

| Mode | Description |
| --- | --- |
| `auth-only` | TCP connections must pass libknock TCP authentication before the application accepts them. |
| `knock-auth-only` | TCP stays open at the transport layer, but clients must knock first and then pass TCP authentication before the application accepts them. No firewall rules are changed. |
| `knock-firewall-auth` | A successful knock opens a short firewall window, then TCP authentication must pass. |
| `knock-firewall-only` | A successful knock opens a short firewall window and the application receives the matching TCP connection. |

`knock-auth-only` is not a port-hiding mode: SYN scans can still report the TCP port as open, but unauthenticated clients cannot reach the application protocol. It does not require root or `CAP_NET_ADMIN`, is useful in containers, restricted VPS instances, Windows/macOS deployments, and adds a short-lived knock session requirement on top of `auth-only`. It does not replace `knock-firewall-auth` when firewall-backed port gating is required.

`knock-firewall-auth` and `knock-firewall-only` require a real firewall backend. `auth-only` and `knock-auth-only` can use `firewall.Noop{}`.

## Relay gateway

`relay.Gateway` is an optional TCP forwarding component. It listens on one address, performs libknock authentication and optional knock/firewall handling, then connects to an upstream TCP service.

```go
gw := relay.Gateway{
    Listen:   ":9000",
    Upstream: "127.0.0.1:19000",
    Auth:     serverAuthConfig,
    Firewall: firewall.Noop{},
}
err := gw.Run(ctx)
```

Use relay when the protected upstream is a separate TCP service rather than an application that embeds `libknock` directly.

## Documentation

- [Documentation index](docs/README.md)
- [Getting started](docs/getting-started.md)
- [Use cases](docs/use-cases.md)
- [API reference](docs/api.md)
- [API surface and compatibility](docs/api-surface.md)
- [Compatibility policy](COMPATIBILITY.md)
- [Protocols](docs/protocols.md)
- [Gate and relay](docs/gate-and-relay.md)
- [Knock methods](docs/knock-methods.md)
- [Firewall backends](docs/firewall.md)
- [Observability](docs/observability.md)
- [Production deployment](docs/production.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Known limitations](docs/known-limitations.md)
- [Validation matrix](docs/validation-matrix.md)
- [Performance notes](docs/performance.md)
- [Roadmap](docs/roadmap.md)
- [Release notes](docs/release-notes.md)
- [Release checklist](docs/release-checklist.md)
- [Development guide](docs/development.md)

## Firewall note

`nftables` and `ipset-iptables` support timeout-oriented rules. The plain `iptables` backend relies on libknock's gate/relay timers to revoke ACCEPT rules and performs managed-chain cleanup at startup/shutdown, so unclean process exits can leave temporary rules until cleanup runs again. For production deployments that need kernel-enforced expiry, prefer `nftables` or `ipset-iptables`.

## Repository layout

```text
protocol/       binary protocol codecs and cryptographic helpers
auth/           server/client authentication, replay cache, secret resolvers
netx/           listener, dialer, buffered connection behavior
knock/          knock senders and listeners
firewall/       firewall backend interfaces and implementations
gate/           SDK listener composition modes
relay/          optional TCP relay gateway
policy/         limiter and ban policy adapters
observability/  event interfaces and metrics adapters
cmd/knock-proxy command entrypoint
examples/       integration examples
```

## Test

```sh
scripts/check.sh
```

For a shorter edit loop:

```sh
go test ./...
go vet ./...
go test -race ./auth ./firewall ./knock ./netx ./policy ./protocol ./relay
```

Prometheus and gRPC integration checks are separate modules:

```sh
go -C observability/prometheus test ./...
go -C test/integration/grpc test ./...
```

## Compatibility command

`cmd/knock-proxy` is a compatibility caller for simple client/server proxy deployments. It is not the full historical knock-proxy product and does not host every optional integration. Embedding applications should prefer the SDK packages directly when they need custom lifecycle, metrics, policy, or application-protocol handling.
