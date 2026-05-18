# TCP echo client example

SDK path: `libknock.Dialer`.

Run with the matching server:

```sh
export LIBKNOCK_SECRET_BASE64=$(openssl rand -base64 32)
go run ./examples/tcp-echo-server &
go run ./examples/tcp-echo-client
```

Expected output contains `echo:hello custom tcp`.

Failure cases: missing/short secret, wrong server address, wrong server port in client config, or replay/time-window rejection.
