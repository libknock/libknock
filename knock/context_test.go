package knock

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestPublicUDPEntrypointsAcceptNilContext(t *testing.T) {
	secret := []byte("0123456789abcdef")
	listener, err := NewUDPListener("127.0.0.1:0", ListenOptions{Port: 443, Clients: []ClientSecret{{ClientID: "client", Secret: secret}}})
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.(interface{ Addr() net.Addr }).Addr().String()

	events := make(chan Event, 1)
	errCh := make(chan error, 1)
	go func() { errCh <- listener.Serve(nil, func(ev Event) { events <- ev }) }()

	if err := SendUDP(nil, SendOptions{ServerAddr: addr, ClientID: "client", Secret: secret, ServerPort: 443}); err != nil {
		t.Fatalf("send with nil context failed: %v", err)
	}

	select {
	case ev := <-events:
		if ev.ClientID != "client" {
			t.Fatalf("unexpected client id %q", ev.ClientID)
		}
		_ = listener.Close()
	case err := <-errCh:
		t.Fatalf("listener exited: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestSleepSequenceIntervalAcceptsNilContext(t *testing.T) {
	seq := SequenceOptions{PacketInterval: time.Millisecond}
	if err := sleepSequenceInterval(nil, 0, 2, seq); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepSequenceInterval(ctx, 0, 2, seq); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
