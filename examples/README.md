# Examples

| Example | Use | Recipe |
| --- | --- | --- |
| `tcp-echo-server` / `tcp-echo-client` | ordinary TCP listener/dialer | `docs/agents/recipes/tcp-listener.md` |
| `tls-server` / `tls-client` | TLS after libknock admission | `docs/agents/recipes/tls-http-server.md` |
| `grpc-server` / `grpc-client` | gRPC integration | `docs/agents/recipes/grpc-server.md` |
| `http-client` | custom HTTP transport/client pattern | `docs/agents/recipes/tls-http-server.md` |
| `custom-binary-protocol` | custom TCP protocol | `docs/agents/recipes/tcp-listener.md` |

Run each example from its directory with the commands in its local README.


## Quick validation

```sh
go build ./examples/tcp-echo-server ./examples/tcp-echo-client
go build ./examples/tls-server ./examples/tls-client
go build ./examples/http-client/server ./examples/http-client/client
go test ./examples/grpc-client/... ./examples/grpc-server/...
```

The gRPC examples are also exercised by `test/integration/grpc`. Keep example READMEs linked from the recipe table above when adding or renaming examples.
