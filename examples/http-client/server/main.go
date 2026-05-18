package main

import (
	"log"
	"net"
	"net/http"
	"os"

	"github.com/libknock/libknock"
	"github.com/libknock/libknock/examples/internal/exampleutil"
)

func main() {
	secret := exampleutil.MustSecret()
	raw, err := net.Listen("tcp", env("LIBKNOCK_ADDR", ":9002"))
	if err != nil {
		log.Fatal(err)
	}
	ln := libknock.WrapListener(raw, libknock.ServerConfig{ServerPort: exampleutil.MustPort(raw.Addr()), Secrets: libknock.NewStaticSecretResolver(map[string][]byte{"client-001": secret})})
	log.Printf("http server listening on %s", raw.Addr())
	log.Fatal(http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })))
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
