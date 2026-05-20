# API surface

`libknock` intentionally separates the stable SDK path from advanced protocol and platform packages.

## Stable root package

Use the root package for normal TCP service integration:

- listener wrapping: `NewListener`, `WrapListener`, `WrapListenerE`
- explicit server object: `NewServer`, `Server`
- one-shot auth: `ServerAuth`, `ClientAuth`
- client dialing: `Dialer`
- configuration and metadata: `ServerConfig`, `ClientConfig`, `PeerInfo`
- stable constants and extension interfaces: `MinSecretSize`, `SecretResolver`, `SecretCandidate`, `ReplayCache`, `KnockSender`, `SessionBoundKnockSender`, `KnockSessionStore`, `EventSink`, `Policy`, `FrameMeta`, `PeerIdentity`

## Stable advanced auth package

Use `auth` when an integration needs protocol selectors, custom secret resolution, replay cache implementations, policy hooks, events, envelope-v2 options, or knock-session binding.

`HintModeRouteHint` is the recommended default for TCP auth envelope v2. `HintModeNone` is deterministic but intended for small candidate sets; if the number of candidates exceeds `MaxAuthAttempts`, authentication fails with `ErrTooManyCandidates` instead of depending on map iteration order.

## Wire-level package

`protocol` is for advanced users who need direct frame/envelope encoding, interoperability tests, or custom transports. Its exported low-level helpers are wire-level release-candidate APIs, not the preferred stable integration surface.

## Platform packages

`knock`, `firewall`, `gate`, `relay`, and `observability` are public advanced packages. Raw packet, passive-capture, SYN, and host firewall paths require target-host validation as documented in the validation matrix and known limitations.

Coding agents should not treat these packages as the default integration surface. Start from the root package or `auth` unless the task explicitly involves knock methods, firewall mutation, gate composition, relay compatibility, or observability adapters. Do not add application config parsing, long-running service orchestration, or product-specific policy to SDK core packages.

## Command package

`cmd/knock-proxy` is maintained as a relay compatibility command. It should not be read as a complete CLI wrapper for every SDK gate mode.
