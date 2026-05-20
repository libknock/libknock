package auth

import (
	"encoding/hex"
	"sync"
	"time"

	"github.com/libknock/libknock/internal/cache"
)

const DefaultReplayCacheMaxEntries = 65536

// MemoryReplayCache stores accepted auth nonces by client. It shares the internal TTL/LRU primitive with other bounded stores, but keeps replay-specific keying and duplicate semantics here.
type MemoryReplayCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	now        func() time.Time
	sweepEvery time.Duration
	nextSweep  time.Time
	maxEntries int
	entries    *cache.TTLLRU[string, struct{}]
}

func NewMemoryReplayCache(ttl time.Duration) *MemoryReplayCache {
	if ttl <= 0 {
		ttl = DefaultTimeWindow * 2
	}
	return NewMemoryReplayCacheWithLimit(ttl, DefaultReplayCacheMaxEntries)
}

func NewMemoryReplayCacheWithLimit(ttl time.Duration, maxEntries int) *MemoryReplayCache {
	if ttl <= 0 {
		ttl = DefaultTimeWindow * 2
	}
	if maxEntries <= 0 {
		maxEntries = DefaultReplayCacheMaxEntries
	}
	return &MemoryReplayCache{ttl: ttl, now: time.Now, sweepEvery: replaySweepInterval(ttl), maxEntries: maxEntries, entries: cache.NewTTLLRU[string, struct{}](maxEntries)}
}

func (c *MemoryReplayCache) CheckAndMark(clientID string, nonce []byte) error {
	if c == nil {
		return nil
	}
	now := c.now()
	key := clientID + "\x00" + hex.EncodeToString(nonce)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nextSweep.IsZero() {
		c.nextSweep = now.Add(c.sweepEvery)
	} else if !now.Before(c.nextSweep) {
		c.entries.Sweep(now)
		c.nextSweep = now.Add(c.sweepEvery)
	}
	if c.entries.ActiveLen(now) >= c.maxEntries {
		c.entries.Sweep(now)
		c.nextSweep = now.Add(c.sweepEvery)
	}
	if c.entries.ActiveLen(now) >= c.maxEntries {
		if _, ok := c.entries.GetAt(key, now); ok {
			return ErrReplayDetected
		}
		return ErrReplayCacheFull
	}
	if !c.entries.AddIfAbsent(key, struct{}{}, now.Add(c.ttl), now) {
		return ErrReplayDetected
	}
	return nil
}

func (c *MemoryReplayCache) Sweep(now time.Time) int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := c.entries.Sweep(now)
	c.nextSweep = now.Add(c.sweepEvery)
	return removed
}

func (c *MemoryReplayCache) Len() int {
	if c == nil {
		return 0
	}
	return c.entries.Len()
}

func replaySweepInterval(ttl time.Duration) time.Duration {
	if ttl <= 30*time.Second {
		return ttl
	}
	return 30 * time.Second
}
