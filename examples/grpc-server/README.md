# gRPC server over libknock

This directory is a small standalone Go module so `google.golang.org/grpc` and protobuf stay out of the core SDK module:

```sh
export LIBKNOCK_SECRET_BASE64=$(openssl rand -base64 32)
go run .
```
