# HTTP over libknock

```sh
export LIBKNOCK_SECRET_BASE64=$(openssl rand -base64 32)
go run ./examples/http-client/server
```

```sh
export LIBKNOCK_SECRET_BASE64=...
go run ./examples/http-client/client
```
