package main

import (
	"context"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/libknock/libknock"
	"github.com/libknock/libknock/auth"
)

func main() {
	secret := mustSecret()
	addr := env("LIBKNOCK_ADDR", "127.0.0.1:9002")
	d := libknock.Dialer{Base: &net.Dialer{Timeout: 5 * time.Second}, Config: libknock.ClientConfig{ClientID: "client-001", Secret: secret, ServerPort: 9002}}
	client := http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return d.DialContext(ctx, network, address)
	}}, Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("status=%s body=%q", resp.Status, body)
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
