package auth

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type denyPolicy struct{}

func (denyPolicy) Allow(string) bool { return false }

type rateLimitEvents struct {
	remote net.Addr
	reason error
}

func (e *rateLimitEvents) OnAccept(net.Addr) {}
func (e *rateLimitEvents) OnAuthOK(PeerInfo) {}
func (e *rateLimitEvents) OnAuthFail(remote net.Addr, reason error) {
	e.remote, e.reason = remote, reason
}
func (e *rateLimitEvents) OnReplay(net.Addr, uint64)     {}
func (e *rateLimitEvents) OnRateLimited(remote net.Addr) { e.remote = remote }

func TestServerAuthPolicyRateLimited(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	events := new(rateLimitEvents)
	_, _, err := ServerAuth(context.Background(), server, ServerConfig{Secrets: StaticSecrets{"client": []byte("0123456789abcdef")}, ReplayCache: NewMemoryReplayCache(time.Minute), Policy: denyPolicy{}, Events: events})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v", err)
	}
	if events.remote == nil {
		t.Fatal("expected rate-limit event remote")
	}
	if !errors.Is(events.reason, ErrRateLimited) {
		t.Fatalf("reason = %v", events.reason)
	}
}
