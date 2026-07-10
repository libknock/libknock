package auth

import (
	"encoding/hex"
	"reflect"
	"sync"
	"time"

	"github.com/libknock/libknock/internal/cache"
)

const DefaultReplayCacheMaxEntries = 65536

func hasReplayCache(cache ReplayCache) bool {
	if cache == nil {
		return false
	}
	value := reflect.ValueOf(cache)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !value.IsNil()
	default:
		return true
	}
}

// MemoryReplayCache stores accepted auth nonces by client. It shares the internal TTL/LRU primitive with other bounded stores, but keeps replay-specific keying and duplicate semantics here.
type MemoryReplayCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	now        func() time.Time
	sweepEvery time.Duration
	nextSweep  time.Time
	maxEntries int
	entries    *cache.TTLLRU[string, struct{}]
	active     int
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
		c.sweepLocked(now)
		c.nextSweep = now.Add(c.sweepEvery)
	}
	if c.active >= c.maxEntries {
		c.sweepLocked(now)
		c.nextSweep = now.Add(c.sweepEvery)
	}
	if c.active >= c.maxEntries {
		if _, ok := c.entries.GetAt(key, now); ok {
			return ErrReplayDetected
		}
		return ErrReplayCacheFull
	}
	if !c.entries.AddIfAbsent(key, struct{}{}, now.Add(c.ttl), now) {
		return ErrReplayDetected
	}
	c.active++
	return nil
}

func (c *MemoryReplayCache) Sweep(now time.Time) int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := c.sweepLocked(now)
	c.nextSweep = now.Add(c.sweepEvery)
	return removed
}

func (c *MemoryReplayCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

func (c *MemoryReplayCache) Cap() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxEntries
}

func (c *MemoryReplayCache) sweepLocked(now time.Time) int {
	removed := c.entries.Sweep(now)
	c.active = c.entries.Len()
	return removed
}

func replaySweepInterval(ttl time.Duration) time.Duration {
	if ttl <= 30*time.Second {
		return ttl
	}
	return 30 * time.Second
}
