# gRPC server over libknock

This example is built from the gRPC integration submodule so gRPC/protobuf do not become core SDK dependencies:

```sh
cd test/integration/grpc
export LIBKNOCK_SECRET_BASE64=$(openssl rand -base64 32)
go run ./examples/grpc-server
```
