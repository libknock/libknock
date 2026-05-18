package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
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
	addr := env("LIBKNOCK_ADDR", "127.0.0.1:9001")
	d := libknock.Dialer{Base: &net.Dialer{Timeout: 5 * time.Second}, Config: libknock.ClientConfig{ClientID: "client-001", Secret: secret, ServerPort: 9001}}
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	msg := []byte(env("LIBKNOCK_MESSAGE", "hello-binary"))
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msg)))
	_, _ = conn.Write(hdr[:])
	_, _ = conn.Write(msg)
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		log.Fatal(err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		log.Fatal(err)
	}
	log.Printf("response: %s", resp)
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
