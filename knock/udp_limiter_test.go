package knock

import (
	"context"
	"net"
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
