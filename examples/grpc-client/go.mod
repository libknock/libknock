module github.com/libknock/libknock/examples/grpc-client

go 1.24.0

require (
	github.com/libknock/libknock v0.1.0-rc3.4
	google.golang.org/grpc v1.75.1
	google.golang.org/protobuf v1.36.8
)

require (
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
)

replace github.com/libknock/libknock => ../..
