package main

import (
	"bufio"
	"context"
	"io"
	"log"
	"net"
	"time"

	"github.com/libknock/libknock"
	"github.com/libknock/libknock/examples/internal/exampleutil"
)

func main() {
	secret := exampleutil.MustSecret()
	addr := exampleutil.Env("LIBKNOCK_ADDR", "127.0.0.1:9000")
	d := libknock.Dialer{Base: &net.Dialer{Timeout: 5 * time.Second}, Config: libknock.ClientConfig{ClientID: "client-001", Secret: secret, ServerPort: 9000, AuthTimeout: 3 * time.Second}}
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "hello custom tcp\n")
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	log.Print(line)
}
