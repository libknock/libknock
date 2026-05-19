package main

import (
	"bufio"
	"context"
	"io"
	"log"
	"net"

	"github.com/libknock/libknock"
	"github.com/libknock/libknock/examples/internal/exampleutil"
)

func main() {
	secret := exampleutil.MustSecret()
	ln, err := net.Listen("tcp", ":9000")
	if err != nil {
		log.Fatal(err)
	}
	ln, err = libknock.NewListener(ln, libknock.ServerConfig{ServerPort: 9000, Secrets: libknock.NewStaticSecretResolver(map[string][]byte{"client-001": secret})})
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handle(context.Background(), conn)
	}
}

func handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			_, _ = conn.Write(append([]byte("echo:"), line...))
		}
		if err != nil {
			if err != io.EOF {
				log.Print(err)
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
