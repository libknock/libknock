package netx

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/libknock/libknock/auth"
)

func TestAuthenticatedListenerDoesNotHeadOfLineBlockOnSlowAuth(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := WrapListenerWithConfig(raw, ListenerConfig{Auth: auth.ServerConfig{ServerPort: mustPort(t, raw.Addr()), Secrets: auth.StaticSecrets{"client": secret}, AuthTimeout: 500 * time.Millisecond}, MaxPendingAuth: 2, MaxAuthWorkers: 2})
	defer wrapped.Close()

	slow, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()

	fast, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ClientAuth(context.Background(), fast, auth.ClientConfig{ClientID: "client", Secret: secret, ServerPort: mustPort(t, raw.Addr())}); err != nil {
		t.Fatal(err)
	}
	defer fast.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := wrapped.Accept()
		if err == nil {
			_ = conn.Close()
		}
		accepted <- err
	}()
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Accept head-of-line blocked behind slow unauthenticated connection")
	}
}

func TestNilListenerReturnsError(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	cfg := ListenerConfig{Auth: auth.ServerConfig{ServerPort: 443, Secrets: auth.StaticSecrets{"client": secret}}}
	if _, err := NewListener(nil, cfg); !errors.Is(err, ErrNilListener) {
		t.Fatalf("NewListener nil err = %v, want ErrNilListener", err)
	}
	if _, err := WrapListenerWithConfigE(nil, cfg); !errors.Is(err, ErrNilListener) {
		t.Fatalf("WrapListenerWithConfigE nil err = %v, want ErrNilListener", err)
	}
	wrapped := WrapListener(nil, cfg.Auth)
	if wrapped == nil {
		t.Fatal("WrapListener returned nil")
	}
	if _, err := wrapped.Accept(); !errors.Is(err, ErrNilListener) {
		t.Fatalf("WrapListener nil Accept err = %v, want ErrNilListener", err)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatalf("WrapListener nil Close err = %v", err)
	}
}

func mustPort(t *testing.T, addr net.Addr) int {
	t.Helper()
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr is %T", addr)
	}
	return tcp.Port
}

func TestWrapListenerWithConfigEReturnsNewServerError(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := WrapListenerWithConfigE(raw, ListenerConfig{Auth: auth.ServerConfig{ServerPort: mustPort(t, raw.Addr())}}); err == nil {
		t.Fatal("expected missing secret resolver error")
	}
}

type sessionRecordingKnocker struct{ got []byte }

func (k *sessionRecordingKnocker) SetSessionID(sessionID []byte) {
	k.got = append([]byte(nil), sessionID...)
}
func (k *sessionRecordingKnocker) Knock(context.Context) error { return nil }

func TestDialerPassesGeneratedSessionIDToKnockerAndAuth(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	server, client := net.Pipe()
	defer server.Close()
	knocker := &sessionRecordingKnocker{}
	d := Dialer{Base: pipeDialer{conn: client}, Config: auth.ClientConfig{ClientID: "client", Secret: secret, ServerPort: 443, Knock: knocker}}
	done := make(chan *auth.PeerInfo, 1)
	go func() {
		cfg := auth.ServerConfig{ServerPort: 443, Secrets: auth.StaticSecrets{"client": secret}, ReplayCache: auth.NewMemoryReplayCache(time.Minute)}
		clean, peer, err := auth.ServerAuth(context.Background(), server, cfg)
		if err != nil {
			done <- nil
			return
		}
		_ = clean.Close()
		done <- peer
	}()
	conn, err := d.DialContext(context.Background(), "tcp", "unused")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	peer := <-done
	if peer == nil {
		t.Fatal("server did not receive auth")
	}
	if len(knocker.got) == 0 || string(knocker.got) != string(peer.SessionID) {
		t.Fatalf("knock session %x peer session %x", knocker.got, peer.SessionID)
	}
}

type pipeDialer struct{ conn net.Conn }

func (d pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

func TestWrapListenerPreservesEarlyApplicationBytes(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := mustPort(t, raw.Addr())
	wrapped := WrapListener(raw, auth.ServerConfig{ServerPort: port, Secrets: auth.StaticSecrets{"client": secret}, AuthTimeout: time.Second})
	defer wrapped.Close()
	done := make(chan string, 1)
	go func() {
		conn, err := wrapped.Accept()
		if err != nil {
			done <- ""
			return
		}
		defer conn.Close()
		buf := make([]byte, len("GET / HTTP/1.1\r\n"))
		_, _ = conn.Read(buf)
		done <- string(buf)
	}()
	conn, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ClientAuth(context.Background(), conn, auth.ClientConfig{ClientID: "client", Secret: secret, ServerPort: port}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n")); err != nil {
		t.Fatal(err)
	}
	if got := <-done; got != "GET / HTTP/1.1\r\n" {
		t.Fatalf("application prefix = %q", got)
	}
	_ = conn.Close()
}

func TestAuthenticatedListenerCloseInterruptsInFlightAuth(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := WrapListenerWithConfig(raw, ListenerConfig{Auth: auth.ServerConfig{ServerPort: mustPort(t, raw.Addr()), Secrets: auth.StaticSecrets{"client": secret}, AuthTimeout: 5 * time.Second}, MaxAuthWorkers: 1})
	client, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan error, 1)
	go func() { _, err := wrapped.Accept(); accepted <- err }()
	select {
	case <-accepted:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Accept did not unblock after Close")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close waited %s, want much less than AuthTimeout", elapsed)
	}
}

type closeRecordingListener struct {
	conn   chan net.Conn
	closed chan struct{}
	err    error
}

func (l *closeRecordingListener) Accept() (net.Conn, error) {
	conn, ok := <-l.conn
	if !ok {
		return nil, l.err
	}
	return conn, nil
}
func (l *closeRecordingListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}
func (l *closeRecordingListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}

func TestAuthenticatedListenerCloseAfterAcceptErrorInterruptsInFlightAuth(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	server, client := net.Pipe()
	defer client.Close()
	raw := &closeRecordingListener{conn: make(chan net.Conn, 1), closed: make(chan struct{}), err: net.ErrClosed}
	raw.conn <- server
	wrapped, err := WrapListenerWithConfigE(raw, ListenerConfig{Auth: auth.ServerConfig{ServerPort: 443, Secrets: auth.StaticSecrets{"client": secret}, AuthTimeout: 5 * time.Second}, MaxAuthWorkers: 1})
	if err != nil {
		t.Fatal(err)
	}
	close(raw.conn)
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-raw.closed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("underlying listener was not closed")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close waited %s after accept error, want much less than AuthTimeout", elapsed)
	}
}
