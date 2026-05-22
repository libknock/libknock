# http-client recipe

## Applicable scenario

HTTP clients and servers that should authenticate the TCP connection before HTTP bytes are exchanged.

## Files to modify

- examples/http-client/, docs/getting-started.md, docs/agents/integration-guide.md
- Update docs/tests next to changed examples.

## Files not to modify

- protocol/, internal/
- Do not teach the SDK core about HTTP routing or headers.
- Do not claim libknock replaces TLS or HTTP authorization.

## Minimal shape

```text
server: wrap a net.Listener with libknock.NewListener, then pass it to http.Server.Serve
client: use libknock.Dialer from a custom http.Transport DialContext
```

## Common mistakes

- Sending HTTP bytes before libknock client authentication completes.
- Creating a replay cache per HTTP request or per connection.
- Putting application config parsing in the SDK core.
- Disabling TLS because libknock is enabled; use HTTPS when transport confidentiality is required.

## Validation commands

```sh
go build ./examples/http-client/server ./examples/http-client/client
bash scripts/check-integration.sh
```
