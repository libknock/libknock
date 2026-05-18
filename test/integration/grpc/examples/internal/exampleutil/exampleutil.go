package exampleutil

import (
	"encoding/base64"
	"log"
	"net"
	"os"

	libknock "github.com/libknock/libknock"
)

func MustSecret() []byte {
	secret, err := base64.StdEncoding.DecodeString(os.Getenv("LIBKNOCK_SECRET_BASE64"))
	if err != nil || len(secret) < libknock.MinSecretSize {
		log.Fatal("set LIBKNOCK_SECRET_BASE64 to at least 16 random bytes")
	}
	return secret
}

func MustPort(addr net.Addr) int {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.Port
	}
	return 0
}
