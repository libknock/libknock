# LLM and coding-agent integration notes

This page is the long-form companion to the repository-level [`llms.txt`](../llms.txt). It is intended for coding agents, IDE assistants, and restricted CI environments that need a compact map of libknock without reading the whole repository first.

## Start here

Read these files before making integration or release-process changes:

1. [`docs/agents/AGENTS.md`](agents/AGENTS.md)
2. [`docs/agents/integration-guide.md`](agents/integration-guide.md)
3. [`docs/agents/task-matrix.yaml`](agents/task-matrix.yaml)
4. [`COMPATIBILITY.md`](../COMPATIBILITY.md)
5. [`docs/api-surface.md`](api-surface.md)

For normal application integrations, prefer the root package:

- server-side Go service: `libknock.NewListener` or `libknock.WrapListenerE`
- client-side Go service: `libknock.Dialer`
- custom connection pipeline: `libknock.NewServer` / `Server.Auth`
- unmodified upstream binary: `relay.Gateway` or `cmd/knock-proxy`

Do not start a normal integration from `protocol/` or `internal/`.

## Workspace and vendor model

The source repository may contain a generated `vendor/` tree during release validation, but vendored dependencies are release artifacts rather than the primary development model.

Release artifacts are intentionally split:

| Artifact | Intended use | Vendor content |
| --- | --- | --- |
| `libknock-VERSION.zip` | normal Go module users | excludes `vendor/` |
| `libknock-VERSION-with-vendor.zip` | offline review, reproducible local audit, LLM-assisted integration, restricted CI | includes `vendor/`, `vendor/modules.txt`, `go.work`, and `go.work.sum` |

When working in a `with-vendor` archive or a checkout with populated `vendor/`, keep `go.work` enabled and run validation from the workspace root. Use explicit vendor mode where practical:

```sh
go test -mod=vendor ./...
go vet -mod=vendor ./...
```

Do not combine `GOWORK=off` with workspace vendor mode; Go will report inconsistent workspace vendor metadata because `vendor/modules.txt` is generated for the workspace.

When changing module metadata, run the release packaging checks instead of hand-editing `vendor/modules.txt`.

## Agent-safe task routing

| Task | Preferred docs | Preferred packages | Avoid |
| --- | --- | --- | --- |
| Protect a Go TCP listener | [`recipes/tcp-listener.md`](agents/recipes/tcp-listener.md), [`getting-started.md`](getting-started.md) | root package, `netx`, `auth` | `protocol/`, per-connection replay caches |
| Add TLS, HTTP, or gRPC after admission | [`recipes/tls-http-server.md`](agents/recipes/tls-http-server.md), [`recipes/grpc-server.md`](agents/recipes/grpc-server.md) | root package examples | treating libknock as a TLS replacement |
| Protect an existing binary | [`recipes/relay-gateway.md`](agents/recipes/relay-gateway.md), [`gate-and-relay.md`](gate-and-relay.md) | `relay`, `cmd/knock-proxy` | adding config-file parsing to SDK core |
| Require knock without firewall privileges | [`recipes/knock-auth-only.md`](agents/recipes/knock-auth-only.md), [`modes.md`](modes.md) | `gate`, `relay`, `knock`, `auth` | claiming port hiding |
| Use host firewall admission | [`recipes/firewall-gate.md`](agents/recipes/firewall-gate.md), [`firewall.md`](firewall.md) | `firewall`, `gate`, `relay` | production claims without target-host validation |
| Release/documentation work | [`release-checklist.md`](release-checklist.md), [`validation-matrix.md`](validation-matrix.md) | docs and scripts only when possible | changing stable API without compatibility docs |

## Required safety boundaries

- Keep replay caches shared for a logical server runtime. Do not allocate one replay cache per connection.
- Keep application config parsing in applications, examples, or `cmd/`; SDK core accepts typed structs.
- Keep secrets, sealed payloads, and raw auth material out of logs, metrics labels, and release notes.
- Treat `auth-only` and `knock-auth-only` as application-protocol admission modes, not port-hiding modes.
- Treat passive capture, TCP SYN methods, and firewall-backed modes as platform-specific until validated on the target host.

## IDE assistant config files

This repository keeps assistant-facing instructions in ordinary tracked Markdown/text files instead of tool-specific hidden policy files. Common IDE integrations should be pointed at:

- `AGENTS.md`
- `llms.txt`
- `docs/llms.md`
- `docs/agents/integration-guide.md`
- `docs/agents/task-matrix.yaml`

If a local IDE requires a generated `.cursorrules`, `CLAUDE.md`, or similar file, derive it from those tracked files and do not make it the source of truth.
