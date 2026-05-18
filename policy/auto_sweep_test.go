package policy

import (
	"testing"
	"time"
)

func TestLimiterAllowSweepsExpiredEntriesPeriodically(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewLimiterWithClock(Window{Limit: 1, Every: time.Second}, ClockFunc(func() time.Time { return now }))
	if !l.Allow("a") {
		t.Fatal("first allow rejected")
	}
	now = now.Add(2 * time.Second)
	if !l.Allow("b") {
		t.Fatal("second allow rejected")
	}
	if got := l.Len(); got != 1 {
		t.Fatalf("Len after periodic sweep = %d, want 1", got)
	}
}

func TestBanListBanSweepsExpiredEntriesPeriodically(t *testing.T) {
	now := time.Unix(0, 0)
	b := NewBanListWithClock(ClockFunc(func() time.Time { return now }))
	b.Ban("a", time.Second)
	now = now.Add(2 * time.Minute)
	b.Ban("b", time.Minute)
	if got := b.Len(); got != 1 {
		t.Fatalf("Len after periodic sweep = %d, want 1", got)
	}
}

func TestLimiterEvictsOldestAtLimit(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewLimiterWithClockAndLimit(Window{Limit: 10, Every: time.Minute}, ClockFunc(func() time.Time { return now }), 1)
	if !l.Allow("old") || !l.Allow("new") {
		t.Fatal("allow rejected")
	}
	if got := l.Len(); got != 1 {
		t.Fatalf("Len = %d, want 1", got)
	}
	if !l.Allow("old") {
		t.Fatal("old key should have been evicted and allowed again")
	}
}

func TestBanListEvictsOldestAtLimit(t *testing.T) {
	now := time.Unix(0, 0)
	b := NewBanListWithClockAndLimit(ClockFunc(func() time.Time { return now }), 1)
	b.Ban("old", time.Hour)
	b.Ban("new", time.Hour)
	if got := b.Len(); got != 1 {
		t.Fatalf("Len = %d, want 1", got)
	}
	if b.IsBanned("old") {
		t.Fatal("old key should have been evicted")
	}
}
