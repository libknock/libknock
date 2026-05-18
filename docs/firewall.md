# Firewall backends

Firewall backends are optional. They are used by `gate` and `relay` knock/firewall modes to create short-lived source-IP access rules for a protected TCP port.

## Backend interface

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

## Built-in backends

| Backend | Summary | Timeout behavior |
| --- | --- | --- |
| `noop` | In-memory no-op backend used for auth-only workflows and tests. | No system rules. |
| `nftables` | Linux nftables backend using `family inet`. | Native timeout-oriented sets. |
| `ipset-iptables` | Linux ipset plus iptables backend. | ipset timeout-oriented entries. |
| `iptables` | Linux iptables backend. | Process-managed revoke and cleanup. |
| `script` | Calls executable paths for allow, revoke, and cleanup. | Defined by scripts. |
| `auto` | Chooses an available Linux backend according to backend detection. | Depends on detected backend. |

## Backend selection

Recommended production order:

```text
nftables
ipset-iptables
iptables
script
```

Use `noop` only for auth-only workflows, tests, and local development.

`auto` detects Linux backends in this order:

```text
nftables -> ipset-iptables -> iptables -> script when configured
```

## Port binding

Firewall backends that install system rules are bound to one protected port. Construct them with `firewall.Config.Port` or let `gate` / `relay.Gateway` inject the effective listener/auth port.

```go
fw, err := firewall.New(firewall.Config{
    Backend: "nftables",
    Port:    9000,
})
```

`Allow`, `Revoke`, and `IsAllowed` validate the same protected port where applicable.

## nftables

The nftables backend uses conservative object names and `family inet`. Sets use explicit timeout flags. Keep configured table, chain, and set names dedicated to `libknock` because cleanup owns those objects.

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

The ipset-iptables backend stores allowed clients in ipset sets and uses iptables rules to reference those sets. It is a good fit for deployments that already standardize on ipset.

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

The iptables backend installs per-client ACCEPT rules and clears them during revoke or cleanup. The `ttl` passed to `Allow` is enforced by the gate/relay timer that later calls `Revoke`; iptables rules themselves do not carry a timeout.

If the hosting process exits unexpectedly, ACCEPT rules can remain until the next `Init`/`Cleanup` pass removes `libknock` managed rules. For production deployments that need kernel-enforced expiry, prefer `nftables` or `ipset-iptables`.

Use a dedicated chain name for the protected service.

```go
fw, err := firewall.New(firewall.Config{
    Backend: "iptables",
    Port:    9000,
    Iptables: firewall.IptablesConfig{
        Chain: "LIBKNOCK",
    },
})
```

## script backend

The script backend calls executable paths directly. It does not run shell command strings.

```text
allow_cmd <remote_ip> <port> <ttl_seconds>
revoke_cmd <remote_ip> <port>
cleanup_cmd <port>
```

Inside scripts, treat arguments as data. Quote positional parameters as `"$1"`, `"$2"`, and `"$3"`; do not `eval` them or concatenate them into shell command strings.

Safe shell template:

```sh
#!/bin/sh
set -eu
remote_addr="$1"
port="$2"
ttl_seconds="${3:-}"
iptables -I LIBKNOCK 1 -s "$remote_addr" -p tcp --dport "$port" -j ACCEPT
```

Example:

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

The script backend does not manage `DropUDPKnockPort`; use `nftables`, `iptables`, or `ipset-iptables` when that option is required.

## drop_udp_knock_port

`DropUDPKnockPort` is intended for UDP passive modes. It asks the firewall backend to manage DROP behavior for the UDP knock port while the server reads packets through packet capture.

Rules:

- Use only with `udp-passive` or `udp-passive-seq`.
- Use a backend that supports the operation.
- Verify the resulting firewall rules in a real environment.

## Gate and relay integration

`GateKnockFirewallAuth`, `GateKnockFirewallOnly`, and relay knock/firewall workflows require a real firewall backend. `GateAuthOnly` and relay auth-only workflows can use `firewall.Noop{}`.

## Cleanup

Call `Cleanup` during controlled shutdown. `gate` and `relay.Gateway` wire cleanup to context cancellation for their managed listeners. For system firewall backends, pair service lifecycle with a shutdown hook in the hosting process or service manager.

For the plain `iptables` backend, cleanup is particularly important because rule expiration is process-managed rather than kernel-managed.

## Capability checks

Use `firewall.Probe` or application-specific diagnostics before enabling a production firewall backend:

```go
res, err := firewall.Probe(ctx, firewall.Config{
    Backend: "nftables",
    Port:    9000,
})
```

Check command availability, effective user privileges, and backend-specific errors before opening the listener.
