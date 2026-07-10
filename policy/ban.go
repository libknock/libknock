package policy

import (
	"sync"
	"time"

	"github.com/libknock/libknock/internal/cache"
)

const DefaultBanListMaxEntries = 65536

// BanList is a TTL set for policy decisions. It reuses the internal cache primitive, while limiter counters remain separate because windowed counting and bans have different semantics.
type BanList struct {
	clock         Clock
	mu            sync.Mutex
	entries       *cache.TTLLRU[string, struct{}]
	lastSweep     time.Time
	sweepInterval time.Duration
}

func NewBanList() *BanList { return NewBanListWithClock(ClockFunc(time.Now)) }
func NewBanListWithClock(clock Clock) *BanList {
	return NewBanListWithClockAndLimit(clock, DefaultBanListMaxEntries)
}
func NewBanListWithClockAndLimit(clock Clock, maxEntries int) *BanList {
	if clock == nil {
		clock = ClockFunc(time.Now)
	}
	if maxEntries <= 0 {
		maxEntries = DefaultBanListMaxEntries
	}
	return &BanList{clock: clock, entries: cache.NewTTLLRU[string, struct{}](maxEntries), sweepInterval: time.Minute}
}

func (b *BanList) Ban(key string, ttl time.Duration) {
	_ = b.BanE(key, ttl)
}

// BanE adds a temporary ban and reports capacity exhaustion. Existing bans
// can always be renewed. Unlike the generic TTL/LRU cache, BanList never
// evicts an active ban to make room for another key.
func (b *BanList) BanE(key string, ttl time.Duration) error {
	if b == nil || key == "" || ttl <= 0 {
		return nil
	}
	return b.BanUntilE(key, b.clock.Now().Add(ttl))
}

func (b *BanList) BanUntil(key string, until time.Time) {
	_ = b.BanUntilE(key, until)
}

// BanUntilE is BanUntil with an explicit capacity result. The legacy void
// method remains fail-closed through IsBanned while the list is saturated.
func (b *BanList) BanUntilE(key string, until time.Time) error {
	if b == nil || key == "" || until.IsZero() {
		return nil
	}
	now := b.clock.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.updateSweepIntervalLocked(until.Sub(now))
	// Capacity is a security boundary: sweep eagerly before deciding whether a
	// new key fits, but never evict a still-active ban by LRU order.
	b.entries.Sweep(now)
	b.lastSweep = now
	if _, exists := b.entries.Peek(key); !exists && b.entries.Len() >= b.entries.Cap() {
		return ErrBanListFull
	}
	b.entries.SetUntil(key, struct{}{}, until)
	return nil
}

func (b *BanList) IsBanned(key string) bool {
	if b == nil || key == "" {
		return false
	}
	return b.IsBannedAt(key, b.clock.Now())
}

func (b *BanList) IsBannedAt(key string, now time.Time) bool {
	if b == nil || key == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.entries.GetAt(key, now)
	if ok {
		return true
	}
	// A caller of the legacy Ban/BanUntil API cannot receive ErrBanListFull.
	// While every slot contains an active ban, reject unknown keys instead of
	// silently allowing an attempted ban that did not fit.
	return b.entries.ActiveLen(now) >= b.entries.Cap()
}

func (b *BanList) Unban(key string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries.Delete(key)
}

func (b *BanList) Sweep(now time.Time) int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.entries.Sweep(now)
}

func (b *BanList) Len() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.entries.Len()
}

func (b *BanList) sweepPeriodicallyLocked(now time.Time) {
	if b.lastSweep.IsZero() {
		b.lastSweep = now
		return
	}
	interval := b.sweepInterval
	if interval <= 0 {
		interval = time.Minute
	}
	if now.Sub(b.lastSweep) < interval {
		return
	}
	b.entries.Sweep(now)
	b.lastSweep = now
}

func (b *BanList) updateSweepIntervalLocked(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	interval := ttl / 2
	if interval <= 0 {
		interval = ttl
	}
	if interval > time.Minute {
		interval = time.Minute
	}
	if b.sweepInterval <= 0 || interval < b.sweepInterval {
		b.sweepInterval = interval
	}
}
