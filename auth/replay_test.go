package auth

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestReplayCacheRejectsSameNonceWithDifferentTimestamp(t *testing.T) {
	c := NewMemoryReplayCache(DefaultTimeWindow)
	nonce := []byte("1234567890123456")
	if err := c.CheckAndMark("client", nonce); err != nil {
		t.Fatalf("first CheckAndMark: %v", err)
	}
	if err := c.CheckAndMark("client", nonce); err != ErrReplayDetected {
		t.Fatalf("second CheckAndMark = %v, want replay", err)
	}
}

func TestReplayCacheSweepsPeriodicallyNotEveryCall(t *testing.T) {
	c := NewMemoryReplayCache(DefaultTimeWindow)
	now := c.now()
	c.now = func() time.Time { return now }
	if err := c.CheckAndMark("client", []byte("nonce-1")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(c.sweepEvery / 2)
	if err := c.CheckAndMark("client", []byte("nonce-2")); err != nil {
		t.Fatal(err)
	}
	if got := c.Len(); got != 2 {
		t.Fatalf("Len before scheduled sweep = %d, want 2", got)
	}
	now = now.Add(c.ttl + time.Second)
	if err := c.CheckAndMark("client", []byte("nonce-3")); err != nil {
		t.Fatal(err)
	}
	if got := c.Len(); got != 1 {
		t.Fatalf("Len after scheduled sweep = %d, want 1", got)
	}
}

type typedNilReplayCache struct{}

func (*typedNilReplayCache) CheckAndMark(string, []byte) error { return nil }

func TestServerAuthRequiresExplicitReplayCache(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	_, _, err := ServerAuth(context.Background(), serverConn, ServerConfig{ServerPort: 443, Secrets: StaticSecrets{"client": []byte("0123456789abcdef0123456789abcdef")}, AuthTimeout: time.Second})
	if !errors.Is(err, ErrMissingReplayCache) {
		t.Fatalf("ServerAuth err = %v, want missing replay cache", err)
	}
}

func TestServerAuthRejectsTypedNilReplayCache(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	var cache *typedNilReplayCache
	_, _, err := ServerAuth(context.Background(), serverConn, ServerConfig{ServerPort: 443, Secrets: StaticSecrets{"client": []byte("0123456789abcdef0123456789abcdef")}, ReplayCache: cache, AuthTimeout: time.Second})
	if !errors.Is(err, ErrMissingReplayCache) {
		t.Fatalf("ServerAuth err = %v, want missing replay cache", err)
	}
}

func TestNewServerReplacesTypedNilReplayCache(t *testing.T) {
	var cache *typedNilReplayCache
	server, err := NewServer(ServerConfig{ServerPort: 443, Secrets: StaticSecrets{"client": []byte("0123456789abcdef0123456789abcdef")}, ReplayCache: cache})
	if err != nil {
		t.Fatal(err)
	}
	if !hasReplayCache(server.cfg.ReplayCache) {
		t.Fatal("NewServer retained typed-nil replay cache")
	}
}

func TestMemoryReplayCacheFailsClosedAtLimit(t *testing.T) {
	c := NewMemoryReplayCacheWithLimit(time.Minute, 2)
	if err := c.CheckAndMark("client", []byte("nonce-1")); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndMark("client", []byte("nonce-2")); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndMark("client", []byte("nonce-3")); !errors.Is(err, ErrReplayCacheFull) {
		t.Fatalf("full cache err = %v, want ErrReplayCacheFull", err)
	}
	if err := c.CheckAndMark("client", []byte("nonce-1")); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("old nonce err = %v, want ErrReplayDetected", err)
	}
}

func TestMemoryReplayCacheSweepsBeforeFull(t *testing.T) {
	c := NewMemoryReplayCacheWithLimit(time.Second, 1)
	now := time.Unix(100, 0)
	c.now = func() time.Time { return now }
	if err := c.CheckAndMark("client", []byte("old")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if err := c.CheckAndMark("client", []byte("new")); err != nil {
		t.Fatalf("expired entry was not swept before full check: %v", err)
	}
}

func TestMemoryReplayCacheConcurrentCheckAndMarkDoesNotExceedLimit(t *testing.T) {
	c := NewMemoryReplayCacheWithLimit(time.Minute, 128)
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed, full := 0, 0
	for i := 0; i < 64; i++ {
		for j := 0; j < 64; j++ {
			wg.Add(1)
			go func(i, j int) {
				defer wg.Done()
				<-start
				err := c.CheckAndMark("client", []byte{byte(i), byte(j), byte(i >> 8), byte(j >> 8)})
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					allowed++
				} else if errors.Is(err, ErrReplayCacheFull) {
					full++
				} else {
					t.Errorf("CheckAndMark err = %v", err)
				}
			}(i, j)
		}
	}
	close(start)
	wg.Wait()
	if allowed != c.Cap() || c.Len() != c.Cap() || full == 0 {
		t.Fatalf("allowed=%d full=%d len=%d cap=%d", allowed, full, c.Len(), c.Cap())
	}
}

func TestMemoryReplayCacheConcurrentSameNonceAllowsOnlyOne(t *testing.T) {
	c := NewMemoryReplayCacheWithLimit(time.Minute, 128)
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed, replayed := 0, 0
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := c.CheckAndMark("client", []byte("same-nonce"))
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				allowed++
			} else if errors.Is(err, ErrReplayDetected) {
				replayed++
			} else {
				t.Errorf("CheckAndMark err = %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if allowed != 1 || replayed != 63 {
		t.Fatalf("allowed=%d replayed=%d, want 1/63", allowed, replayed)
	}
}
