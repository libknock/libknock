# License and notices

The project license is recorded in the repository `LICENSE` file. Release archives should include `LICENSE` and `NOTICE` when present.

## Dependency policy

- Keep runtime dependencies minimal.
- Optional integrations should stay in submodules when they add heavy dependencies.
- Vendored sources are third-party code and should not be reformatted as part of repository gofmt cleanup.

## Release review

Before an RC archive is published:

```sh
go list -m all
```

Record direct dependencies and any required notices in the release notes. The main release archive does not include vendor/. If a dependency license is unclear, do not claim the release package is license-reviewed until the ambiguity is resolved.
