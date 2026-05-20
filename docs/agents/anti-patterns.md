# Integration anti-patterns

## Per-connection replay cache

Wrong: create `NewMemoryReplayCache` inside every accept loop iteration.

Right: create one cache per logical server runtime, or let `NewListener` / `NewServer` own it.

Reason: replay protection must span connections within the replay window.

## Starting from protocol/

Wrong: application code imports `protocol/` and hand-writes frames.

Right: use root `Dialer`, `NewListener`, or `ServerAuth`.

Reason: wire-level packages are for compatibility and advanced protocol work.

## Unsafe knock parsing

Wrong: call `ParseKnockFrameUnsafe` in a UDP listener exposed to the network.

Right: call `OpenKnockFrame` with a shared replay cache or use the high-level knock listeners.

Reason: unsafe parsing intentionally skips replay protection.

## SDK reads application config

Wrong: add `RunServer(configPath)` to SDK core.

Right: parse config in `cmd/` or the embedding application, then pass typed configs to the SDK.
