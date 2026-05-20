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


Repository validation for Linux firewall backends is currently code-level and dry-run oriented. It covers backend construction, command generation, mock/fake runner behavior, cleanup shape, idempotency paths, and error propagation. It does not prove real rule creation, revoke, cleanup, packet filtering, IPv4/IPv6 behavior, repeated startup cleanup of stale rules, or abnormal-exit recovery on a target host. Treat `nftables`, `ipset-iptables`, and `iptables` fallback as `not validated on real host` until recorded with `docs/validation-template.md`.

## Built-in backends

| Backend | Summary | Timeout behavior |
| --- | --- | --- |
| `noop` | In-memory no-op backend used for auth-only workflows and tests. | No system rules. |
| `nftables` | Linux nftables backend using `family inet`. | Native timeout-oriented sets. |
| `ipset-iptables` | Linux ipset plus iptables backend. | ipset timeout-oriented entries. |
| `iptables` | Linux iptables backend. | Process-managed revoke and cleanup. |
| `script` | Calls executable paths for allow, revoke, and cleanup. | Defined by scripts. |
| `auto` | Chooses an available Linux backend according to backend detection. | Depends on detected backend. |

## Defaults and IPv6

`allow_seconds` defaults to 15 seconds when the SDK or CLI constructs a timeout-capable backend directly. `iptables` and `ipset-iptables` keep IPv6 auto-detection by default, but deployments can set `enable_ipv6: false` to force IPv4-only operation in containers or minimal systems where `ip6tables` exists but cannot be used safely.

## Backend selection

Recommended production order:

```text
nftables
ipset-iptables
iptables
script
```

Use `noop` only for auth-only workflows, knock-auth-only workflows, tests, and local development. It records no host firewall state and must not be described as port hiding.

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

The nftables backend owns and deletes its configured table during cleanup. Use only a libknock-owned nftables table such as `knock_gateway`, `knock_proxy`, `knock_gateway_*`, `knock_proxy_*`, or `libknock_*`. System tables such as `filter`, `nat`, `mangle`, `raw`, and `security` are rejected to avoid deleting host firewall policy.


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

The iptables backend is the compatibility fallback. It installs per-client ACCEPT rules and clears them during revoke or cleanup. The `ttl` passed to `Allow` is enforced by the gate/relay timer that later calls `Revoke`; iptables rules themselves do not carry a timeout.

Risk profile:

- Prefer `nftables` or `ipset-iptables` for production because those backends can use kernel-managed expiry.
- Use plain `iptables` only when the host cannot provide nftables or ipset.
- If the hosting process exits unexpectedly, ACCEPT rules can remain until the next `Init`/`Cleanup` pass removes `libknock` managed rules.
- Operators should run manual cleanup or restart the service to trigger startup cleanup after an unclean exit.

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

- Use only with `udp-passive` or `udp-passive-seq`; active UDP listeners should not DROP their own socket input.
- The process needs packet-capture privileges such as root, `CAP_NET_RAW`, or platform-specific pcap/BPF rights before this mode can observe dropped packets.
- Use a backend that supports the operation.
- Verify the resulting firewall rules and packet-capture behavior in a real environment. Repository tests only cover code paths and command shape.

Validation checklist:

1. Start passive UDP listener with `DropUDPKnockPort` enabled.
2. Confirm the firewall backend creates a DROP rule for the UDP knock port without blocking the protected TCP port.
3. Send a valid UDP knock from a remote host and confirm packet capture still observes it.
4. Confirm the subsequent TCP auth succeeds only for the knocked source.
5. Stop the service and confirm cleanup removes the UDP DROP rule and temporary TCP allow rules.
6. On failure, run backend cleanup or remove the managed chain/set/rules, then restart with `DropUDPKnockPort` disabled.


Real-host validation checklist for system backends:

1. Create a controlled test service and initialize the selected backend (`nftables`, `ipset-iptables`, or `iptables`).
2. Confirm a valid knock creates only libknock-owned rules/sets for the expected source IP and protected port.
3. Confirm revoke removes the temporary allow entry.
4. Confirm cleanup removes managed chains/tables/sets/rules without touching unrelated host policy.
5. Repeat startup and verify stale managed rules from the previous run are cleaned.
6. Simulate abnormal exit, then run startup cleanup or manual cleanup and verify no temporary allow rule remains.
7. Repeat IPv4 and IPv6 cases when the deployment enables both families.

## Gate and relay integration

`GateKnockFirewallAuth`, `GateKnockFirewallOnly`, and relay knock/firewall workflows require a real firewall backend. `GateAuthOnly` and relay auth-only workflows can use `firewall.Noop{}`.

## Failure semantics

Firewall-backed gate and relay modes should fail closed when a backend cannot initialize, allow a client, or record the lease needed for later revoke. Cleanup and revoke failures are surfaced through errors and gateway firewall-error events; operators should alert on them and verify host state.

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

Check command availability, effective user privileges, and backend-specific errors before opening the listener. `DescribeWithConfig` and `Probe` use `Config.Runner` when provided, so dry-run and doctor-style integrations can report command availability from their fake runner instead of always probing the host `PATH`.

## Firewall failure semantics

- `allow` failure does not create an authenticated session and must be surfaced as a firewall error event.
- TCP authentication failure never enters the upstream protocol.
- `revoke` and `cleanup` treat already-missing rules, sets, or elements as success, but permission errors, lock failures, syntax errors, and backend command failures are returned.
- Cleanup uses a detached short-timeout context on shutdown or rollback so cancelled serve contexts do not skip firewall cleanup.
- Public peers should receive only connection/auth failure behavior; detailed firewall errors belong in local logs/events.
