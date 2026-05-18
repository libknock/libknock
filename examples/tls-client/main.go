package main

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/libknock/libknock"
	"github.com/libknock/libknock/examples/internal/exampleutil"
)

func main() {
	secret := exampleutil.MustSecret()
	addr := env("LIBKNOCK_ADDR", "127.0.0.1:9003")
	d := libknock.Dialer{Base: &net.Dialer{Timeout: 5 * time.Second}, Config: libknock.ClientConfig{ClientID: "client-001", Secret: secret, ServerPort: 9003}}
	base, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer base.Close()
	// InsecureSkipVerify is only for this local example; production clients must verify the server certificate.
	conn := tls.Client(base, &tls.Config{ServerName: "localhost", InsecureSkipVerify: true})
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		log.Fatal(err)
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("response: %s", body)
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
