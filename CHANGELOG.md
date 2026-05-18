# Changelog

## v0.1.0-rc1 - 2026-05-18

See [docs/release-notes/v0.1.0-rc1.md](docs/release-notes/v0.1.0-rc1.md).

### Release status

- Published as a GitHub pre-release candidate.
- Main source archives do not include `vendor/`; Go modules are the supported dependency path.
- Keep `go.work` / `go.work.sum` for local multi-module resolution; they are workspace metadata, not vendored dependencies.
- Offline builds require a populated local module cache or an internal dependency mirror.

### Security and protocol hardening

- `MemoryReplayCache` and `policy.BanList` are race-safe around periodic sweep state and cache operations.
- Replay detection uses atomic check-and-mark semantics.
- `auth.ServerAuth`, `(*auth.Server).Auth`, `auth.ClientAuth`, and `auth.ClientAuthWithInfo` now reject nil connections with `auth.ErrNilConn` instead of panicking.
- `knock-auth-only` requires a knock session ID and binds TCP auth to the recorded knock session.
- Expired or wrong knock sessions are rejected before application traffic is exposed.
- Envelope v2 frame-size buckets are limited to `128`, `192`, `256`, `384`, and `512`; unsupported configured buckets fail validation with `protocol.ErrInvalidFrameSizeBucket`.
- Envelope v2 `HintModeNone` candidate handling is deterministic. Built-in resolvers sort candidates by client ID and no-hint candidate overflow fails explicitly with `auth.ErrTooManyCandidates`.
- Legacy `knock-proxy/tcp-syn-seq/v1` SYN sequence compatibility is opt-in via `SequenceOptions.AllowLegacySYNSeq`; the default namespace is `libknock/tcp-syn-seq/v1`.

### API surface

- Root package facade now aliases stable extension interfaces: `SecretResolver`, `SecretCandidate`, `ReplayCache`, `KnockSender`, `SessionBoundKnockSender`, `KnockSessionStore`, `EventSink`, `Policy`, `FrameMeta`, and `PeerIdentity`.
- Added [COMPATIBILITY.md](COMPATIBILITY.md) and [docs/api-surface.md](docs/api-surface.md) to mark the root package and most auth APIs as the stable SDK surface, while documenting `protocol`, raw packet/platform `knock`, `firewall`, `gate`, and `relay` as advanced or experimental where appropriate.
- `cmd/knock-proxy` is documented as a relay compatibility entrypoint, not a unified CLI for every SDK gate mode.

### Runtime and shutdown behavior

- `AuthenticatedListener.Close` interrupts in-flight auth attempts instead of waiting for the full auth timeout.
- Gate and relay cleanup keep detached firewall cleanup semantics through `CleanupFirewallDetached` so shutdown still attempts best-effort firewall cleanup after parent contexts are cancelled.
- Relay child goroutine errors preserve the first root-cause error instead of masking it with listener-close noise.

### Repository and release process

- Removed tracked `vendor/` content and added `/vendor/` to `.gitignore`.
- Packaging scripts explicitly exclude `vendor/` from release archives.
- CI and local release gates use Go modules, run nested module checks, verify Prometheus both with workspace replacement and `GOWORK=off`, run race smoke tests, vet, example builds, and cross-platform compile checks.
- Examples now share common secret/port helpers through `examples/internal/exampleutil` where practical.
- Removed dead or unused helpers from relay events, knock, firewall, and Windows packet paths.

### Validation status

- Automated validation covers unit tests, race smoke tests, vet, fuzz smoke, dry-run firewall command checks, localhost integration, nested Prometheus/gRPC modules, example builds, release archive checks, and cross-platform compilation.
- Firewall-backed gates, UDP passive capture, TCP SYN capture paths, Windows packet capture, macOS packet capture, and long-running fuzz/performance characterization require target-host validation before production claims.
