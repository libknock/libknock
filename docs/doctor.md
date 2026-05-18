# knock-proxy doctor

`knock-proxy doctor --config server.yaml` checks whether a compatibility server configuration can be parsed, built, and probed for the selected backend.

## Check classes

| Class | Exit behavior | Examples |
| --- | --- | --- |
| Blocking failure | exits non-zero | config parse failure, unsupported backend, firewall probe failure, missing root for non-noop firewall, missing `CAP_NET_ADMIN`, missing `CAP_NET_RAW` for SYN modes, upstream connection failure when `--check-upstream` is set |
| Warning | exits zero | non-root when backend is `noop`, informational command absence that is not required by selected backend |
| Info | exits zero | parsed config summary, selected backend, discovered command paths |

## Dry-run boundary

`dry-run` and `doctor` can validate configuration shape, backend construction, command availability, and basic command/probe paths. They cannot prove that real firewall rules are inserted in the intended chain order, that host policy allows packet capture, or that traffic is actually dropped/allowed. Use the platform validation scripts and record the result separately before claiming hardware validation.
