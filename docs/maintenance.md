# Maintenance notes

The project intentionally keeps shared runtime mechanics internal unless they are part of the embedding API.

## Duplication boundaries

- Gate/relay shared runtime belongs in `internal/gatewaycore`.
- Generic TTL/LRU mechanics belong in `internal/cache`, but replay caches, knock sessions, ban lists, and rate limiters keep their domain semantics in their own packages.
- Repeated binary parsing belongs in `internal/codec`.
- Repeated cryptographic primitives belong in `internal/cryptox`.
- Example-only helpers belong under `examples/internal/exampleutil` and must not become public API.

Run `scripts/check-duplication.sh` during review. It is warning-only so it does not block intentional duplication in tests or small protocol-specific code.
