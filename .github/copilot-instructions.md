# GitHub Copilot instructions for libknock

Follow the repository source-of-truth docs instead of inventing integration patterns:

- `AGENTS.md`
- `llms.txt`
- `docs/llms.md`
- `docs/agents/AGENTS.md`
- `docs/agents/integration-guide.md`
- `docs/agents/task-matrix.yaml`

Default to the root package for normal integrations: `libknock.NewListener` for servers and `libknock.Dialer` for clients. Do not start normal application integrations from `protocol/` or `internal/`.

Keep replay caches shared for a logical server runtime; never create one replay cache per connection. Keep application config parsing outside SDK core. Do not claim libknock replaces TLS, mTLS, SSH, WireGuard, or application authorization.

For release/docs changes, keep validation claims conservative: unit tests, dry-run firewall scripts, and loopback checks are not real-host firewall or packet-capture validation.
