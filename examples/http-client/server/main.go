package main

import (
	"encoding/base64"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/libknock/libknock"
	"github.com/libknock/libknock/auth"
)

func main() {
	secret := mustSecret()
	raw, err := net.Listen("tcp", env("LIBKNOCK_ADDR", ":9002"))
	if err != nil {
		log.Fatal(err)
	}
	ln := libknock.WrapListener(raw, libknock.ServerConfig{ServerPort: mustPort(raw.Addr()), Secrets: auth.StaticSecrets{"client-001": secret}})
	log.Printf("http server listening on %s", raw.Addr())
	log.Fatal(http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })))
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
func mustPort(addr net.Addr) int {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.Port
	}
	return 0
}
