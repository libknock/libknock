package policy

import (
	"time"

	"github.com/libknock/libknock/internal/cache"
)

const DefaultBanListMaxEntries = 65536

// BanList is a TTL set for policy decisions. It reuses the internal cache primitive, while limiter counters remain separate because windowed counting and bans have different semantics.
type BanList struct {
	clock     Clock
	entries   *cache.TTLLRU[string, struct{}]
	lastSweep time.Time
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
	return &BanList{clock: clock, entries: cache.NewTTLLRU[string, struct{}](maxEntries)}
}

func (b *BanList) Ban(key string, ttl time.Duration) {
	if b == nil || key == "" || ttl <= 0 {
		return
	}
	b.BanUntil(key, b.clock.Now().Add(ttl))
}

func (b *BanList) BanUntil(key string, until time.Time) {
	if b == nil || key == "" || until.IsZero() {
		return
	}
	now := b.clock.Now()
	b.sweepPeriodically(now)
	b.entries.SetUntil(key, struct{}{}, until)
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
	_, ok := b.entries.GetAt(key, now)
	return ok
}

func (b *BanList) Unban(key string) {
	if b == nil {
		return
	}
	b.entries.Delete(key)
}

func (b *BanList) Sweep(now time.Time) int {
	if b == nil {
		return 0
	}
	return b.entries.Sweep(now)
}

func (b *BanList) Len() int {
	if b == nil {
		return 0
	}
	return b.entries.Len()
}

func (b *BanList) sweepPeriodically(now time.Time) {
	if b.lastSweep.IsZero() {
		b.lastSweep = now
		return
	}
	if now.Sub(b.lastSweep) < time.Minute {
		return
	}
	b.entries.Sweep(now)
	b.lastSweep = now
}
