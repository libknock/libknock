# Custom binary protocol

Run two terminals:

```sh
export LIBKNOCK_SECRET_BASE64=$(openssl rand -base64 32)
go run ./examples/custom-binary-protocol/server
```

```sh
export LIBKNOCK_SECRET_BASE64=...
go run ./examples/custom-binary-protocol/client
```
