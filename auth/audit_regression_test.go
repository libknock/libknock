package auth

import (
	"context"
	"net"
	"testing"
	"time"
)

// A caller context with a far deadline must not extend AuthTimeout: an idle
// peer that never sends a frame is dropped after AuthTimeout.
func TestServerAuthTimeoutNotExtendedByLongContextDeadline(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	cfg := ServerConfig{
		Secrets:     StaticSecrets{"client-001": []byte("0123456789abcdef0123456789abcdef")},
		ReplayCache: NewMemoryReplayCache(time.Minute),
		AuthTimeout: 50 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := ServerAuth(ctx, server, cfg)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ServerAuth succeeded for idle peer")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServerAuth ignored AuthTimeout because of a long context deadline")
	}
}
