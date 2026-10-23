package netx

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/libknock/libknock/auth"
)

type fixedRemoteConn struct {
	net.Conn
	remote net.Addr
}

func (c fixedRemoteConn) RemoteAddr() net.Addr { return c.remote }

// A single source must not be able to occupy every auth slot when the operator
// sets MaxPendingAuthPerSource.
func TestAuthenticatedListenerEnforcesPerSourceLimit(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	raw := &closeRecordingListener{conn: make(chan net.Conn, 4), closed: make(chan struct{}), err: net.ErrClosed}
	events := &authDropRecorder{ch: make(chan authDropEvent, 4)}
	wrapped, err := WrapListenerWithConfigE(raw, ListenerConfig{Auth: auth.ServerConfig{ServerPort: 443, Secrets: auth.StaticSecrets{"client": secret}, AuthTimeout: 5 * time.Second}, MaxPendingAuth: 8, MaxAuthWorkers: 4, MaxPendingAuthPerSource: 1, Events: events})
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	attacker := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1}
	sameSlash64 := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 2}
	other := &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 3}

	s1, c1 := net.Pipe()
	defer c1.Close()
	raw.conn <- fixedRemoteConn{Conn: s1, remote: attacker}
	time.Sleep(50 * time.Millisecond)
	s2, c2 := net.Pipe()
	defer c2.Close()
	raw.conn <- fixedRemoteConn{Conn: s2, remote: sameSlash64}
	select {
	case ev := <-events.ch:
		if !errors.Is(ev.reason, ErrAuthSourceLimit) {
			t.Fatalf("drop reason = %v", ev.reason)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected per-source drop for second connection from same /64")
	}
	s3, c3 := net.Pipe()
	defer c3.Close()
	raw.conn <- fixedRemoteConn{Conn: s3, remote: other}
	select {
	case ev := <-events.ch:
		t.Fatalf("unexpected drop for other source: %v", ev.reason)
	case <-time.After(150 * time.Millisecond):
	}
}
