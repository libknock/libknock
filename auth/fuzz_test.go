package auth

import (
	"context"
	"net"
	"testing"
	"time"
)

func FuzzServerAuthMalformedInput(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 0, 0})
	f.Add([]byte("not a libknock frame"))
	f.Fuzz(func(t *testing.T, data []byte) {
		client, server := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			_, _, _ = ServerAuth(ctx, server, ServerConfig{
				Secrets:     StaticSecrets{"client": []byte("0123456789abcdef0123456789abcdef")},
				ReplayCache: NewMemoryReplayCache(time.Minute),
				AuthTimeout: 25 * time.Millisecond,
			})
		}()
		_ = client.SetDeadline(time.Now().Add(25 * time.Millisecond))
		_, _ = client.Write(data)
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("ServerAuth did not return")
		}
	})
}
