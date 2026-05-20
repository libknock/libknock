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

## rc2.2 security behavior changes

- Replay caches fail closed when full. Operators should size replay caches for expected concurrent windows and alert on `ErrReplayCacheFull`; the cache will not evict still-valid nonces.
- `knock.OpenKnockFrame` now requires `ServerConfig.ReplayCache`. Use the high-level UDP/passive/sequence listeners for default replay-cache ownership, or use `ParseKnockFrameUnsafe` only for offline diagnostics.
- Limiters reject new keys when all buckets are active and `maxEntries` is reached. Increase `maxEntries` for legitimate high-cardinality traffic rather than relying on LRU eviction.
