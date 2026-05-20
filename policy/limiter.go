package policy

import (
	"container/list"
	"sync"
	"time"
)

const DefaultLimiterMaxEntries = 65536

// Limiter keeps per-key rolling-window counters. It intentionally does not use
// internal/cache.TTLLRU: rate limiting needs mutable counters, LRU eviction, and
// window resets rather than a simple TTL set.
type Limiter struct {
	mu         sync.Mutex
	window     Window
	clock      Clock
	entries    map[string]*bucket
	order      *list.List
	lastSweep  time.Time
	maxEntries int
}

type bucket struct {
	key   string
	start time.Time
	used  int
	elem  *list.Element
}

func NewLimiter(window Window) *Limiter {
	return NewLimiterWithClock(window, ClockFunc(time.Now))
}

func NewLimiterWithClock(window Window, clock Clock) *Limiter {
	return NewLimiterWithClockAndLimit(window, clock, DefaultLimiterMaxEntries)
}

func NewLimiterWithClockAndLimit(window Window, clock Clock, maxEntries int) *Limiter {
	if clock == nil {
		clock = ClockFunc(time.Now)
	}
	if maxEntries <= 0 {
		maxEntries = DefaultLimiterMaxEntries
	}
	return &Limiter{window: window.WithDefaults(), clock: clock, entries: make(map[string]*bucket), order: list.New(), maxEntries: maxEntries}
}

func (l *Limiter) Allow(key string) bool {
	if l == nil {
		return true
	}
	return l.AllowAt(key, l.clock.Now())
}

func (l *Limiter) AllowAt(key string, now time.Time) bool {
	if l == nil {
		return true
	}
	if key == "" {
		key = "default"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepPeriodicallyLocked(now)
	if len(l.entries) >= l.maxEntries {
		l.sweepLocked(now)
	}
	b := l.entries[key]
	if b == nil && len(l.entries) >= l.maxEntries {
		return false
	}
	if b == nil || !now.Before(b.start.Add(l.window.Every)) {
		if b != nil {
			l.removeBucketLocked(b)
		}
		b = &bucket{key: key, start: now, used: 1}
		b.elem = l.order.PushBack(b)
		l.entries[key] = b
		return true
	}
	l.order.MoveToBack(b.elem)
	if b.used >= l.window.Limit {
		return false
	}
	b.used++
	return true
}

func (l *Limiter) Check(key string) error {
	if l.Allow(key) {
		return nil
	}
	return ErrRateLimited
}

func (l *Limiter) Sweep(now time.Time) int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sweepLocked(now)
}

func (l *Limiter) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

func (l *Limiter) sweepPeriodicallyLocked(now time.Time) {
	if l.window.Every <= 0 {
		return
	}
	if l.lastSweep.IsZero() {
		l.lastSweep = now
		return
	}
	interval := l.window.Every / 2
	if interval <= 0 || interval > time.Minute {
		interval = time.Minute
	}
	if now.Sub(l.lastSweep) < interval {
		return
	}
	for _, b := range l.entries {
		if !now.Before(b.start.Add(l.window.Every)) {
			l.removeBucketLocked(b)
		}
	}
	l.lastSweep = now
}

func (l *Limiter) sweepLocked(now time.Time) int {
	removed := 0
	for _, b := range l.entries {
		if !now.Before(b.start.Add(l.window.Every)) {
			l.removeBucketLocked(b)
			removed++
		}
	}
	return removed
}

func (l *Limiter) removeBucketLocked(b *bucket) {
	delete(l.entries, b.key)
	if b.elem != nil {
		l.order.Remove(b.elem)
		b.elem = nil
	}
}
