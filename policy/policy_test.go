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
