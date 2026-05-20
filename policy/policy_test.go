package policy

import (
	"errors"
	"testing"
	"time"
)

type fakeClock struct{ now time.Time }

func (f *fakeClock) Now() time.Time { return f.now }

func TestLimiterWindow(t *testing.T) {
	fc := &fakeClock{now: time.Unix(100, 0)}
	l := NewLimiterWithClock(Window{Limit: 2, Every: time.Second}, fc)
	first := l.Allow("a")
	second := l.Allow("a")
	if !first || !second {
		t.Fatal("first two attempts should pass")
	}
	if l.Allow("a") {
		t.Fatal("third attempt should be limited")
	}
	fc.now = fc.now.Add(time.Second)
	if !l.Allow("a") {
		t.Fatal("new window should pass")
	}
}

func TestBanListExpires(t *testing.T) {
	fc := &fakeClock{now: time.Unix(100, 0)}
	b := NewBanListWithClock(fc)
	b.Ban("a", time.Second)
	if !b.IsBanned("a") {
		t.Fatal("expected banned")
	}
	fc.now = fc.now.Add(time.Second)
	if b.IsBanned("a") {
		t.Fatal("ban should expire")
	}
}

func TestGuardBansAfterRateLimit(t *testing.T) {
	g := NewGuard(Window{Limit: 1, Every: time.Minute}, time.Minute)
	if err := g.Check("a"); err != nil {
		t.Fatal(err)
	}
	if err := g.Check("a"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v", err)
	}
	if !g.Bans.IsBanned("a") {
		t.Fatal("expected ban after rate limit")
	}
}

func TestLimiterFailsClosedWhenFull(t *testing.T) {
	now := time.Unix(100, 0)
	l := NewLimiterWithClockAndLimit(Window{Limit: 2, Every: time.Minute}, ClockFunc(func() time.Time { return now }), 2)
	if !l.Allow("a") || !l.Allow("b") {
		t.Fatal("initial keys should pass")
	}
	if l.Allow("c") {
		t.Fatal("new key should be rejected while all buckets are active")
	}
	if !l.Allow("a") {
		t.Fatal("existing key should keep its active bucket")
	}
	if l.Allow("a") {
		t.Fatal("existing key count was reset or limit was bypassed")
	}
	now = now.Add(time.Minute)
	if !l.Allow("c") {
		t.Fatal("expired bucket should be swept and reused")
	}
}

func TestBanListShortTTLSweepInterval(t *testing.T) {
	fc := &fakeClock{now: time.Unix(100, 0)}
	b := NewBanListWithClock(fc)
	b.Ban("short", 20*time.Millisecond)
	fc.now = fc.now.Add(25 * time.Millisecond)
	if b.IsBanned("short") {
		t.Fatal("expired ban should not be active")
	}
	b.Ban("other", time.Second)
	if got := b.Len(); got != 1 {
		t.Fatalf("Len after short-ttl periodic sweep = %d, want 1", got)
	}
}
