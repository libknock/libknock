# Changelog

## v0.1.0-rc3.2 - 2026-05-22

See [docs/release-notes/v0.1.0-rc3.2.md](docs/release-notes/v0.1.0-rc3.2.md).

### Release scope

- Recovered CI by making the workspace vendor tree available to GitHub Actions and documenting that vendor validation runs from the workspace root with `go.work` enabled.
- Hardened release scripts: strict duplication scans now fail when `dupl` is missing, and release packaging has a non-git source-tree fallback.
- Added code-quality guards for shared firewall cleanup, netx auth-backpressure observability, EnvelopeV2 `HintModeNone` candidate validation, TTLLRU length semantics, `NewGateway` config copying, public auth-error labeling, and firewall missing-object matching.
- Clarified README knock-method support, workspace vendor/LLM guidance, IDE assistant pointers, agent recipes, and validation-update task routing.
- Added an rc3.2 validation record that separates local release gates from platform-specific target-host validation.

### Validation status

- Full release gate must pass before publishing: vendor-mode test/vet/build, race subset, nested Prometheus/gRPC/examples checks, API/doc/duplication checks, `scripts/check.sh`, `scripts/release-check.sh`, archive packaging, and sha256 verification.
- Real-host firewall validation, Windows/macOS packet-path validation, long fuzz, and production throughput remain outside current-host claims unless separately recorded.


## v0.1.0-rc3.1 - 2026-05-22

See [docs/release-notes/v0.1.0-rc3.1.md](docs/release-notes/v0.1.0-rc3.1.md).


## v0.1.0-rc3 - 2026-05-22

See [docs/release-notes/v0.1.0-rc3.md](docs/release-notes/v0.1.0-rc3.md).


## v0.1.0-rc2.6 - 2026-05-20

### Release scope

- Normalized low-level `knock` public entrypoints to accept a nil `context.Context` consistently with auth/netx/gate/relay APIs. Nil contexts are converted to `context.Background()` before dialing, raw socket send, BPF/AF_PACKET listeners, UDP listeners, and sequence sleeps.
- Removed an unused firewall command helper and kept command detection on the Runner-aware path used by backend detection and diagnostics.
- Aligned nested gRPC example and integration modules plus the optional Prometheus module on `github.com/libknock/libknock v0.1.0-rc2.6` while preserving local `replace` directives.
- Kept release checks focused on project-owned Go files, representative examples, API snapshot, vendored archive validation, docs links, fuzz smoke, benchmark smoke, and maintainer duplication checks.

### Validation status

- Automated gates cover unit/integration tests, selected race tests, vet/build, docs links, API surface snapshot, short fuzz smoke, benchmark smoke, duplication scan, vendored archive checks, nested modules, and representative examples.
- This pre-release still does not claim real-host validation for nftables, ipset-iptables, iptables fallback, UDP passive with `drop_udp_knock_port`, TCP SYN paths, Windows WinDivert/Npcap paths, macOS BPF/pcap paths, long fuzz campaigns, or production performance baselines. Use `docs/validation-template.md` before making deployment-specific production claims.

## v0.1.0-rc2.5 - 2026-05-20

### Release scope

- Hardened `scripts/release-check.sh` so vendored release validation runs in a temporary checkout and does not remove an existing working-tree `vendor/` directory.
- Updated `observability/prometheus` to depend on `github.com/libknock/libknock v0.1.0-rc2.5` for the matching pre-release line and normalized nested gRPC example protobuf versions for workspace vendor consistency.
- Added `scripts/check-api.sh`, a root-package export snapshot in `docs/api-surface.md`, and release-checklist API-gate guidance.
- Added `scripts/fuzz-long.sh` and `scripts/benchmark.sh` for longer fuzz and benchmark evidence covering protocol, knock, auth, replay cache, sequence tracker, and gate paths.
- Clarified that envelope v2 client `FrameSizeBuckets` must stay within server `MaxFrameSize`.
- Strengthened release and production documentation for iptables fallback cleanup risk, UDP passive privileges, firewall validation plans, artifact audit commands, Chinese checklist parity, and conservative platform-validation status.

### Validation status

- Automated gates cover source tests, vet, race smoke, nested modules, representative fuzz smoke, benchmark smoke, API snapshot, vendored archive validation, docs links, duplication scan, and package archive checks.
- Real-host validation is still required before production claims for Linux firewall enforcement, UDP passive/drop interaction, TCP SYN paths, Windows packet integrations, macOS packet integrations, long fuzz campaigns, and production performance characterization.

## v0.1.0-rc2.4 - 2026-05-20

See [docs/release-notes/v0.1.0-rc2.4.md](docs/release-notes/v0.1.0-rc2.4.md).

### Release scope

- Harden firewall cleanup/rollback, revoke idempotency, `IsAllowed` error propagation, nftables table safety, default allow seconds, and IPv4-only configuration.
- Improve `knock-proxy` firewall summaries and doctor visibility for noop/non-port-hiding modes.
- Complete standard vs `with-vendor` packaging docs/scripts, release validation gates, validation matrix, and agent recipes.

## v0.1.0-rc2.3 - 2026-05-20

See [docs/release-notes/v0.1.0-rc2.3.md](docs/release-notes/v0.1.0-rc2.3.md).

### Release status

- Published as a GitHub pre-release candidate.
- Keeps the standard archive module-first while documenting the companion `with-vendor` archive for offline audit, restricted CI, reproducible local review, and LLM-assisted integration.

### Documentation and release process

- Clarifies validation-matrix and known-limitations wording for firewall backends, passive UDP capture, TCP SYN paths, Windows/macOS packet integrations, long-running fuzz, and production performance characterization.
- Reinforces `auth-only` and `knock-auth-only` semantics: the TCP listener remains visible; application protocol admission is authenticated.
- Documents `iptables` as a process-managed cleanup fallback and recommends `nftables` or `ipset-iptables` where kernel-enforced expiry is required.

## v0.1.0-rc2 - 2026-05-19

See [docs/release-notes/v0.1.0-rc2.md](docs/release-notes/v0.1.0-rc2.md).

### Release status

- Published as a GitHub pre-release candidate.
- Focuses on release-candidate hardening findings without changing the SDK boundary: libknock remains an embeddable TCP pre-application auth library, not a config-owning server.

### Hardening

- Firewall gate cleanup failures are now observable through `FirewallError` events and aggregated `Gate.Close` errors.
- Auth listener workers use a listener-owned cancellable context plus per-connection auth timeout.
- Dialer client configuration is validated before knock or TCP side effects.
- SYN replay cache uses internal locking, atomic add-if-absent, and hex nonce keying.
- Server proof nonce/prefix comparisons use the project constant-time helper.
- Policy fallback keys are more specific for custom or malformed remote addresses.


### RC2.x hardening

- Replay caches and knock replay paths now fail closed at capacity instead of evicting active nonces.
- `knock.OpenKnockFrame` now requires a replay cache; no-replay parsing is isolated behind `ParseKnockFrameUnsafe`.
- `AuthenticatedListener` auth timeout cancellation is scoped per connection, not per worker lifetime.
- Policy limiters reject new keys at full active capacity; active buckets are not evicted by high-cardinality traffic.
- Short-TTL bans sweep on a TTL-derived interval.
- `TTLLRU.Len()` is documented as a stored-entry upper bound and `ActiveLen(now)` provides exact active counts.
- Script firewall `Init()` validates command configuration without executing allow/revoke/cleanup.

### API and release process

- Added root `NewListener` and `WrapListenerE` error-returning listener APIs.
- Release scripts are more robust when execute bits are lost, and strict duplication checks fail on missing tooling.
- License, CI/local release gate, and release notes documentation were clarified.

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
