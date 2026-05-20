# Security model

`libknock` is a pre-application TCP admission SDK. It narrows which connections reach the application protocol, but it is not a complete transport or application security system.

## Boundaries

- It does not replace TLS, mTLS, SSH, WireGuard, or business authorization.
- It does not encrypt application bytes after authentication; the returned `net.Conn` is the caller's normal stream.
- It authenticates before the application protocol starts and preserves any bytes over-read during auth.
- Firewall-backed modes depend on the selected backend and host policy. Repository dry-run tests are not hardware validation.

## Failure handling

- Peer-facing failures are quiet connection closes; detailed local errors are for the embedding application, logs, tests, and event sinks.
- Event sinks must not emit shared secrets, sealed payloads, complete frames, raw auth material, or unbounded error strings.
- Prometheus labels normalize method and reason values to bounded sets; unknown method values become `unknown` and unclassified errors become `error`.

## State windows

- `AuthTimeout` bounds the time spent reading authentication material.
- `TimeWindow` bounds acceptable client timestamps.
- `ReplayCache` rejects duplicate auth nonces across connections and should be shared by `ServerAuth` callers. It fails closed when full: expired entries are swept first, then new nonces are rejected rather than evicting still-valid nonces.
- `KnockNonceTTL` / knock replay caches reject duplicate knock frames.
- Knock session TTL and `MaxConnectionsPerKnock` bind a successful knock to later TCP auth attempts when session binding is enabled.
- Active UDP knock listeners can use `ListenOptions.PacketLimiter` to reject packets by source IP before AEAD opening. Enable this for public UDP knock ports so floods do not force candidate-secret work.

## Secrets

Secrets should come from operator-controlled configuration, files, KMS, or another resolver. Do not log secrets or serialize them into event payloads. Resolver/backend failures should remain locally diagnosable without revealing details to remote peers.

## Low-level knock parsing

`knock.OpenKnockFrame` is a server authentication API and requires a shared replay cache. `knock.ParseKnockFrameUnsafe` exists only for offline diagnostics and tests; it must not be used for public server admission paths because it skips replay protection.
