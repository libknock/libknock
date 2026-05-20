# Agent instructions

Read this before changing code, examples, docs, public APIs, or integration behavior.

## Default integration path

- Use the root package first.
- Server-side Go services should prefer `NewListener` or `WrapListener`.
- Clients should prefer `Dialer`.
- Custom `net.Conn` pipelines may use `NewServer` / `Server.Auth` or `ServerAuth`, but `ServerAuth` callers must provide one shared replay cache per logical server runtime.
- Use relay only for unmodified upstream binaries.

## Do not

- Do not start from `protocol/` for normal application integration.
- Do not create a replay cache per connection.
- Do not put YAML, JSON, TOML, or env parsing in SDK core. Configuration parsing belongs in `cmd/` or examples.
- Do not add `RunServer(configPath)` to the SDK.
- Do not claim libknock replaces TLS, mTLS, or application authorization.
- Do not call `knock.ParseKnockFrameUnsafe` on public server authentication paths.

## Public API discipline

Stable root APIs are documented in `docs/api-surface.md` and `COMPATIBILITY.md`. Changing them requires updating compatibility docs, examples, recipes, and release notes.

## Required completion report

State files changed, why, validation commands run, environment-limited tests not run, public API impact, and whether English/Chinese docs stayed synchronized.
