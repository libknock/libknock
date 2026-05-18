package main

import (
	"encoding/base64"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"

	"github.com/libknock/libknock"
	"github.com/libknock/libknock/auth"
)

func main() {
	secret := mustSecret()
	ln, err := net.Listen("tcp", env("LIBKNOCK_ADDR", ":9001"))
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	ln = libknock.WrapListener(ln, libknock.ServerConfig{ServerPort: mustPort(ln.Addr()), Secrets: auth.StaticSecrets{"client-001": secret}})
	log.Printf("custom binary server listening on %s", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		log.Print(err)
		return
	}
	msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(conn, msg); err != nil {
		log.Print(err)
		return
	}
	resp := append([]byte("ack:"), msg...)
	binary.BigEndian.PutUint16(hdr[:], uint16(len(resp)))
	_, _ = conn.Write(hdr[:])
	_, _ = conn.Write(resp)
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
