# TLS server over libknock

```sh
export LIBKNOCK_SECRET_BASE64=$(openssl rand -base64 32)
go run ./examples/tls-server
```
