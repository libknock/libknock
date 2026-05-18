package libknock

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/libknock/libknock/auth"
)

func TestPlainTCPEchoWrapListenerAndDialer(t *testing.T) {
	secret := testSecret()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	cfg := ServerConfig{ServerPort: mustPort(t, raw.Addr()), Secrets: auth.StaticSecrets{"client-a": secret}, AuthTimeout: time.Second}
	ln := WrapListener(raw, cfg)
	serveErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serveErr <- err
			return
		}
		defer conn.Close()
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			serveErr <- err
			return
		}
		_, err = io.WriteString(conn, "echo:"+line)
		serveErr <- err
	}()
	d := &Dialer{Config: ClientConfig{ClientID: "client-a", Secret: secret, ServerPort: cfg.ServerPort}}
	conn, err := d.DialContext(context.Background(), "tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "hello custom tcp\n"); err != nil {
		t.Fatal(err)
	}
	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if got != "echo:hello custom tcp\n" {
		t.Fatalf("got %q", got)
	}
	if err := <-serveErr; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestPlainTCPEchoWrapListenerAndDialerEnvelopeV2(t *testing.T) {
	secret := testSecret()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	cfg := ServerConfig{ServerPort: mustPort(t, raw.Addr()), Secrets: auth.StaticSecrets{"client-a": secret}, AuthTimeout: time.Second, Protocol: auth.AuthProtocolEnvelopeV2, AcceptProtocols: []auth.AuthProtocol{auth.AuthProtocolEnvelopeV2}}
	ln := WrapListener(raw, cfg)
	serveErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serveErr <- err
			return
		}
		defer conn.Close()
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			serveErr <- err
			return
		}
		_, err = io.WriteString(conn, "echo:"+line)
		serveErr <- err
	}()
	d := &Dialer{Config: ClientConfig{ClientID: "client-a", Secret: secret, ServerPort: cfg.ServerPort, Protocol: auth.AuthProtocolEnvelopeV2}}
	conn, err := d.DialContext(context.Background(), "tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "hello v2 tcp\n"); err != nil {
		t.Fatal(err)
	}
	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if got != "echo:hello v2 tcp\n" {
		t.Fatalf("got %q", got)
	}
	if err := <-serveErr; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
