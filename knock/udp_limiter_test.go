package knock

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/libknock/libknock/auth"
)

type packetLimiterFunc func(net.IP) bool

func (f packetLimiterFunc) Allow(ip net.IP) bool { return f(ip) }

func TestUDPPacketLimiterPreventsReplayMark(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	replay := auth.NewMemoryReplayCache(time.Minute)
	listener, err := NewUDPListener("127.0.0.1:0", ListenOptions{Port: 443, Clients: []ClientSecret{{ClientID: "client", Secret: secret}}, ReplayCache: replay, PacketLimiter: packetLimiterFunc(func(net.IP) bool { return false })})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- listener.Serve(ctx, func(Event) {}) }()
	conn, err := net.Dial("udp", listener.(interface{ Addr() net.Addr }).Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	nonce := []byte("0123456789abcdef")
	frame, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: secret, ServerPort: 443, Method: UDPMethod, Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := replay.CheckAndMark("client", nonce); err != nil {
		t.Fatalf("limited packet marked replay cache: %v", err)
	}
	cancel()
	if err := <-errCh; err != context.Canceled {
		t.Fatalf("Serve err = %v, want context canceled", err)
	}
}

func TestUDPListenerServeDoesNotRetainContextWatcherAfterReadFailure(t *testing.T) {
	baseline := runtime.NumGoroutine()
	for range 32 {
		listener := &udpListener{conn: failingPacketConn{}, opts: ListenOptions{Clients: []ClientSecret{{ClientID: "client", Secret: []byte("0123456789abcdef0123456789abcdef")}}}}
		if err := listener.Serve(context.Background(), func(Event) {}); err == nil {
			t.Fatal("Serve succeeded with failing packet connection")
		}
	}
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > baseline+8 && time.Now().Before(deadline) {
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline+8 {
		t.Fatalf("context watcher goroutines leaked: got %d, baseline %d", got, baseline)
	}
}

type failingPacketConn struct{}

func (failingPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (failingPacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, net.ErrClosed }
func (failingPacketConn) Close() error                           { return nil }
func (failingPacketConn) LocalAddr() net.Addr                    { return &net.UDPAddr{} }
func (failingPacketConn) SetDeadline(time.Time) error            { return nil }
func (failingPacketConn) SetReadDeadline(time.Time) error        { return nil }
func (failingPacketConn) SetWriteDeadline(time.Time) error       { return nil }

func TestUDPPacketLimiterRunsBeforeOpen(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	listener, err := NewUDPListener("127.0.0.1:0", ListenOptions{Port: 443, Clients: []ClientSecret{{ClientID: "client", Secret: secret}}, PacketLimiter: packetLimiterFunc(func(net.IP) bool { return false })})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handled := make(chan struct{}, 1)
	errCh := make(chan error, 1)
	go func() { errCh <- listener.Serve(ctx, func(Event) { handled <- struct{}{} }) }()
	conn, err := net.Dial("udp", listener.(interface{ Addr() net.Addr }).Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	frame, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: secret, ServerPort: 443, Method: UDPMethod})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handled:
		t.Fatal("limited UDP packet reached handler")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if err := <-errCh; err != context.Canceled {
		t.Fatalf("Serve err = %v, want context canceled", err)
	}
}
