package cache

import (
	"testing"
	"time"
)

func TestTTLLRULenAndActiveLen(t *testing.T) {
	c := NewTTLLRU[string, int](4)
	now := time.Unix(100, 0)
	c.SetUntil("expired", 1, now.Add(-time.Second))
	c.SetUntil("active", 2, now.Add(time.Second))
	if got := c.Len(); got != 2 {
		t.Fatalf("Len = %d, want stored upper bound 2", got)
	}
	if got := c.ActiveLen(now); got != 1 {
		t.Fatalf("ActiveLen = %d, want 1", got)
	}
}
