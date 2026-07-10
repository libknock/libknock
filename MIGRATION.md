# cmd/knock-proxy integration notes

`cmd/knock-proxy` is a command entrypoint built on top of the SDK packages. The command reads product configuration, converts it into typed libknock values, builds adapters, and starts the requested runtime.

## Configuration mapping

| Product concept | SDK value |
| --- | --- |
| protected TCP port | `ServerConfig.ServerPort` and `firewall.Config.Port` |
| client ID and secret | `auth.StaticSecrets`, `auth.RotatingSecrets`, or a custom `SecretResolver` |
| auth timeout | `ServerConfig.AuthTimeout` / `ClientConfig.AuthTimeout` |
| replay window | `ServerConfig.TimeWindow` plus a server-lifetime `ReplayCache` |
| knock method | `gate.Config.KnockMethod` or `relay.Gateway.KnockMethod` |
| knock clients | `[]knock.ClientSecret` |
| firewall backend | `firewall.New(firewall.Config{Backend: ..., Port: ...})` |
| forwarding entrypoint | `relay.Gateway` |
| SDK-integrated server | `WrapListener`, `NewServer`, or `gate.Listen` |

## Mode mapping

| Command-level mode | SDK composition |
| --- | --- |
| TCP authentication at listener boundary | `libknock.WrapListener`, `NewServer`, or `GateAuthOnly` |
| knock + firewall + TCP authentication | `GateKnockFirewallAuth` |
| knock + firewall listener admission | `GateKnockFirewallOnly` |
| TCP forwarding gateway | `relay.Gateway` |

## Runtime responsibilities

The command entrypoint owns:

- YAML parsing
- CLI flags
- process startup and shutdown
- dry-run and doctor command flow
- product-level defaults
- adapter wiring

## Configuration hardening and default knock method

`cmd/knock-proxy` accepts exactly one YAML document and rejects unknown fields. Correct configuration-key typos before upgrading; they are no longer ignored. Numeric configuration values must be zero or positive, and `secret` and `secret_file` are mutually exclusive for both `client` and each `auth.clients[]` entry.

When `knock.method` is omitted, both client and server now select `udp`. Earlier compatibility-command defaults could select `tcp-syn` on some platforms. Set `knock.method: tcp-syn` explicitly before upgrading if that raw-packet behavior is required. The UDP listener defaults to the protected TCP port unless `knock.udp_listen`, `knock.udp_knock_port`, or `knock.udp_port` sets another port.

SDK packages own:

- TCP auth protocols
- UDP knock frame handling
- replay cache behavior
- listener and dialer wrappers
- firewall backend interfaces
- event interfaces
- optional policy hooks

## Operational notes

- Use one replay cache per logical server runtime.
- Use `NewServer` or `WrapListener` for server-owned replay cache lifecycle.
- Use a dedicated firewall chain/table/set for libknock-managed rules.
- Run firewall cleanup during controlled shutdown.
- Keep client secrets dedicated to libknock usage.
- Keep Prometheus wiring in the embedding application or command runtime.

## Rollback plan

Keep service configs versioned. To roll back a deployment, stop the current runtime, run firewall cleanup for the configured backend and protected port, restore the previous service config, and restart the previous runtime.

## rc2.x security behavior changes

- Replay caches fail closed when full. Operators should size replay caches for expected concurrent windows and alert on `ErrReplayCacheFull`; the cache will not evict still-valid nonces.
- `knock.OpenKnockFrame` now requires `ServerConfig.ReplayCache`. Use the high-level UDP/passive/sequence listeners for default replay-cache ownership, or use `ParseKnockFrameUnsafe` only for offline diagnostics.
- Limiters reject new keys when all buckets are active and `maxEntries` is reached. Increase `maxEntries` for legitimate high-cardinality traffic rather than relying on LRU eviction.

## Legacy TCP SYN sequence compatibility

New deployments use the `libknock/tcp-syn-seq/v1` namespace. The older `knock-proxy/tcp-syn-seq/v1` namespace remains available only when `SequenceOptions.AllowLegacySYNSeq` is set. Enable it for controlled migration windows, then remove it after all clients have switched to the libknock namespace.
