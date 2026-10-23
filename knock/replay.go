package knock

import (
	"encoding/hex"
	"sync"
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/internal/cache"
)

func replayCache(opts ListenOptions) auth.ReplayCache {
	if opts.ReplayCache != nil {
		return opts.ReplayCache
	}
	// Remember nonces for at least the full +/- TimeWindow acceptance span so
	// a captured frame cannot be replayed after its entry expires.
	ttl := 5 * time.Minute
	if window := opts.TimeWindow; window > 0 && 2*window+time.Second > ttl {
		ttl = 2*window + time.Second
	}
	return auth.NewMemoryReplayCache(ttl)
}

const defaultSYNReplayCacheMaxEntries = 65536

type synReplayCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	sweepEvery time.Duration
	nextSweep  time.Time
	maxEntries int
	entries    *cache.TTLLRU[string, struct{}]
}

func newSYNReplayCache(ttl time.Duration) *synReplayCache {
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	return &synReplayCache{ttl: ttl, sweepEvery: synReplaySweepInterval(ttl), maxEntries: defaultSYNReplayCacheMaxEntries, entries: cache.NewTTLLRU[string, struct{}](defaultSYNReplayCacheMaxEntries)}
}

func (c *synReplayCache) CheckAndMark(clientID string, nonce []byte) error {
	if c == nil {
		return nil
	}
	now := time.Now()
	key := clientID + "\x00" + hex.EncodeToString(nonce)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nextSweep.IsZero() {
		c.nextSweep = now.Add(c.sweepEvery)
	} else if !now.Before(c.nextSweep) {
		c.entries.Sweep(now)
		c.nextSweep = now.Add(c.sweepEvery)
	}
	// Len is an O(1) upper bound on active entries; only pay for an O(n) sweep
	// when the cache looks full. After a sweep Len equals the active count.
	if c.entries.Len() >= c.maxEntries {
		c.entries.Sweep(now)
		c.nextSweep = now.Add(c.sweepEvery)
	}
	if c.entries.Len() >= c.maxEntries {
		if _, ok := c.entries.GetAt(key, now); ok {
			return auth.ErrReplayDetected
		}
		return auth.ErrReplayCacheFull
	}
	if !c.entries.AddIfAbsent(key, struct{}{}, now.Add(c.ttl), now) {
		return auth.ErrReplayDetected
	}
	return nil
}

func synReplaySweepInterval(ttl time.Duration) time.Duration {
	if ttl <= 30*time.Second {
		return ttl
	}
	return 30 * time.Second
}
