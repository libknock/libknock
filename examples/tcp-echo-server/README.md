# TCP echo server example

SDK path: `libknock.WrapListener` around a normal TCP listener.

Run:

```sh
export LIBKNOCK_SECRET_BASE64=$(openssl rand -base64 32)
go run ./examples/tcp-echo-server
```

The server accepts only connections that first complete libknock TCP authentication. Application bytes after the auth frame are echoed back with an `echo:` prefix.

Failure cases: missing/short secret or a client that connects without libknock auth.
