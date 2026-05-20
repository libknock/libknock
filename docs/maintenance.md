# Maintenance notes

The project intentionally keeps shared runtime mechanics internal unless they are part of the embedding API.

## Duplication boundaries

- Gate/relay shared runtime belongs in `internal/gatewaycore`.
- Generic TTL/LRU mechanics belong in `internal/cache`, but replay caches, knock sessions, ban lists, and rate limiters keep their domain semantics in their own packages.
- Repeated binary parsing belongs in `internal/codec`.
- Repeated cryptographic primitives belong in `internal/cryptox`.
- Example-only helpers belong under `examples/internal/exampleutil` and must not become public API.

Run `scripts/check-duplication.sh` during review. Normal review mode is warning-only so it does not block intentional duplication in tests or small protocol-specific code. Release maintainers run `DUPL_THRESHOLD=120 STRICT=1 scripts/check-duplication.sh`, which requires `dupl` (`go install github.com/mibk/dupl@latest`) and fails when the tool is missing or reports duplicates. Normal users do not need the maintainer-only strict gate to build, test, or embed the SDK; missing `dupl` should be read as a tooling prerequisite for release maintainers, not a project-code failure.
