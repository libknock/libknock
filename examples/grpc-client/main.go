package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"os"
	"time"

	libknock "github.com/libknock/libknock"
	"github.com/libknock/libknock/examples/internal/exampleutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/emptypb"
)

func main() {
	secret := exampleutil.MustSecret()
	addr := env("LIBKNOCK_ADDR", "127.0.0.1:9004")
	d := libknock.Dialer{
		Base: &net.Dialer{Timeout: 5 * time.Second},
		Config: libknock.ClientConfig{
			ClientID:   "client-001",
			Secret:     secret,
			ServerPort: 9004,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(
		ctx,
		"passthrough:///"+addr,
		grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", address)
		}),
		// InsecureSkipVerify is only for this local example; production clients must verify the server certificate.
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ServerName: "localhost", InsecureSkipVerify: true})),
		grpc.WithBlock(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	var out emptypb.Empty
	if err := conn.Invoke(context.Background(), "/libknock.example.Pinger/Ping", &emptypb.Empty{}, &out); err != nil {
		log.Fatal(err)
	}
	log.Print("grpc ping ok")
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
