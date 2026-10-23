package relay

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/netx"
)

// A single auth worker must not be pinned by a long-lived relayed session:
// after the first client authenticates and keeps its session open, a second
// client must still be able to authenticate and relay.
func TestGatewayLongLivedSessionDoesNotStarveAuthWorkers(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := probe.Addr().String()
	_ = probe.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Gateway{
			Listen:                 listen,
			Upstream:               upstream.Addr().String(),
			Auth:                   auth.ServerConfig{ServerPort: mustPort(t, listen), Secrets: auth.StaticSecrets{"client-001": secret}},
			UpstreamConnectTimeout: time.Second,
			IdleTimeout:            10 * time.Second,
			MaxAuthWorkers:         1,
		}.Run(ctx)
	}()
	waitTCP(t, listen)
	d := netx.Dialer{Config: auth.ClientConfig{ClientID: "client-001", Secret: secret, ServerPort: mustPort(t, listen), AuthTimeout: time.Second}}
	echo := func(conn net.Conn, msg string) {
		t.Helper()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("echo %q: %v", msg, err)
		}
		if string(buf) != msg {
			t.Fatalf("echo = %q, want %q", buf, msg)
		}
	}
	first, err := d.DialContext(context.Background(), "tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	echo(first, "one")
	second, err := d.DialContext(context.Background(), "tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	echo(second, "two")
	cancel()
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("gateway did not stop")
	}
}
