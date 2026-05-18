package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/libknock/libknock"
	"github.com/libknock/libknock/auth"
)

func main() {
	secret := mustSecret()
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

func mustSecret() []byte {
	secret, err := base64.StdEncoding.DecodeString(os.Getenv("LIBKNOCK_SECRET_BASE64"))
	if err != nil || len(secret) < auth.MinSecretSize {
		log.Fatal("set LIBKNOCK_SECRET_BASE64 to at least 16 random bytes")
	}
	return secret
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
