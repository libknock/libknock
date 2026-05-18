
## Unreleased

- Main source archives no longer include `vendor/`; Go modules are the supported dependency path.
- Keep `go.work` / `go.work.sum` for local multi-module resolution; they are workspace metadata, not vendored dependencies.
- `knock-auth-only` now requires a knock session ID and binds TCP auth to the recorded knock session.
- Legacy `knock-proxy/tcp-syn-seq/v1` SYN sequence compatibility is opt-in via sequence compatibility settings.

# Changelog

## v0.1.0-rc1 - unreleased

See [docs/release-notes/v0.1.0-rc1.md](docs/release-notes/v0.1.0-rc1.md).

### Highlights

- Root package API narrowed to the core SDK entry points; advanced gateway, firewall, knock, relay, and observability APIs live in subpackages.
- Gate knock listener readiness is synchronous for active UDP methods.
- Gate returned listeners own gate lifecycle and cleanup.
- UDP knock requires binary AEAD frames; legacy JSON knock packets are not supported.
- Release validation docs now separate unit/integration/dry-run coverage from hardware validation.

### Validation status

Firewall-backed gates, UDP passive capture, TCP SYN capture paths, Windows packet capture, macOS packet capture, and long-running fuzz/performance characterization require manual validation before production claims.
