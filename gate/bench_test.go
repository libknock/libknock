package gate

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/libknock/libknock/auth"
)

func BenchmarkGateAuthOnlyAccept(b *testing.B) {
	secret := testSecret()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	g, err := New(Config{Mode: AuthOnly, Auth: auth.ServerConfig{ServerPort: benchPort(b, raw.Addr()), Secrets: auth.StaticSecrets{"client": secret}, AuthTimeout: time.Second}})
	if err != nil {
		b.Fatal(err)
	}
	ln, err := g.Wrap(context.Background(), raw)
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		done := make(chan error, 1)
		go func() {
			c, err := ln.Accept()
			if err == nil {
				_ = c.Close()
			}
			done <- err
		}()
		conn, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		if err := auth.ClientAuth(context.Background(), conn, auth.ClientConfig{ClientID: "client", Secret: secret, ServerPort: benchPort(b, raw.Addr())}); err != nil {
			b.Fatal(err)
		}
		_ = conn.Close()
		if err := <-done; err != nil {
			b.Fatal(err)
		}
	}
}

func benchPort(b testing.TB, addr net.Addr) int {
	b.Helper()
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		b.Fatalf("addr is %T", addr)
	}
	return tcp.Port
}
