package knock

import (
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/internal/cache"
)

func replayCache(opts ListenOptions) auth.ReplayCache {
	if opts.ReplayCache != nil {
		return opts.ReplayCache
	}
	return auth.NewMemoryReplayCache(5 * time.Minute)
}

const defaultSYNReplayCacheMaxEntries = 65536

type synReplayCache struct {
	ttl        time.Duration
	sweepEvery time.Duration
	nextSweep  time.Time
	entries    *cache.TTLLRU[string, struct{}]
}

func newSYNReplayCache(ttl time.Duration) *synReplayCache {
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	return &synReplayCache{ttl: ttl, sweepEvery: synReplaySweepInterval(ttl), entries: cache.NewTTLLRU[string, struct{}](defaultSYNReplayCacheMaxEntries)}
}

func (c *synReplayCache) CheckAndMark(clientID string, nonce []byte) error {
	if c == nil {
		return nil
	}
	now := time.Now()
	if c.nextSweep.IsZero() {
		c.nextSweep = now.Add(c.sweepEvery)
	} else if !now.Before(c.nextSweep) {
		c.entries.Sweep(now)
		c.nextSweep = now.Add(c.sweepEvery)
	}
	key := clientID + "\x00" + string(nonce)
	if _, ok := c.entries.GetAt(key, now); ok {
		return auth.ErrReplayDetected
	}
	c.entries.SetUntil(key, struct{}{}, now.Add(c.ttl))
	return nil
}

func synReplaySweepInterval(ttl time.Duration) time.Duration {
	if ttl <= 30*time.Second {
		return ttl
	}
	return 30 * time.Second
}
