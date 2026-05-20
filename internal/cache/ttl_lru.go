package cache

import (
	"container/list"
	"sync"
	"time"
)

type Entry[K comparable, V any] struct {
	Key       K
	Value     V
	ExpiresAt time.Time
}

type TTLLRU[K comparable, V any] struct {
	mu         sync.Mutex
	entries    map[K]*list.Element
	order      *list.List
	maxEntries int
}

func NewTTLLRU[K comparable, V any](maxEntries int) *TTLLRU[K, V] {
	if maxEntries <= 0 {
		maxEntries = 1
	}
	return &TTLLRU[K, V]{entries: make(map[K]*list.Element), order: list.New(), maxEntries: maxEntries}
}

func (c *TTLLRU[K, V]) Set(key K, value V, ttl time.Duration) {
	c.SetUntil(key, value, time.Now().Add(ttl))
}

func (c *TTLLRU[K, V]) SetUntil(key K, value V, expiresAt time.Time) {
	if c == nil || expiresAt.IsZero() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setLocked(key, value, expiresAt)
}

func (c *TTLLRU[K, V]) AddIfAbsent(key K, value V, expiresAt, now time.Time) bool {
	if c == nil || expiresAt.IsZero() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.entries[key]; ok {
		entry := elem.Value.(*Entry[K, V])
		if entry.ExpiresAt.After(now) {
			c.order.MoveToBack(elem)
			return false
		}
		c.removeElementLocked(elem)
	}
	c.setLocked(key, value, expiresAt)
	return true
}

func (c *TTLLRU[K, V]) Peek(key K) (Entry[K, V], bool) {
	var zero Entry[K, V]
	if c == nil {
		return zero, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.entries[key]
	if !ok {
		return zero, false
	}
	return *elem.Value.(*Entry[K, V]), true
}

func (c *TTLLRU[K, V]) Get(key K) (V, bool) {
	return c.GetAt(key, time.Now())
}

func (c *TTLLRU[K, V]) GetAt(key K, now time.Time) (V, bool) {
	var zero V
	if c == nil {
		return zero, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.entries[key]
	if !ok {
		return zero, false
	}
	entry := elem.Value.(*Entry[K, V])
	if !entry.ExpiresAt.After(now) {
		c.removeElementLocked(elem)
		return zero, false
	}
	c.order.MoveToBack(elem)
	return entry.Value, true
}

func (c *TTLLRU[K, V]) DeleteExpired(key K, now time.Time) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.entries[key]
	if !ok {
		return false
	}
	entry := elem.Value.(*Entry[K, V])
	if now.Before(entry.ExpiresAt) {
		return false
	}
	c.removeElementLocked(elem)
	return true
}

func (c *TTLLRU[K, V]) Delete(key K) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.entries[key]
	if !ok {
		return false
	}
	c.removeElementLocked(elem)
	return true
}

func (c *TTLLRU[K, V]) DeleteWhere(match func(Entry[K, V]) bool) int {
	if c == nil || match == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for elem := c.order.Front(); elem != nil; {
		next := elem.Next()
		entry := *elem.Value.(*Entry[K, V])
		if match(entry) {
			c.removeElementLocked(elem)
			removed++
		}
		elem = next
	}
	return removed
}

// Len returns the number of stored entries. The count is an upper bound for
// active entries because expired entries remain counted until a read or Sweep
// removes them. Use ActiveLen when callers need an exact active count.
func (c *TTLLRU[K, V]) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *TTLLRU[K, V]) ActiveLen(now time.Time) int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	active := 0
	for elem := c.order.Front(); elem != nil; elem = elem.Next() {
		entry := elem.Value.(*Entry[K, V])
		if entry.ExpiresAt.After(now) {
			active++
		}
	}
	return active
}

func (c *TTLLRU[K, V]) Sweep(now time.Time) int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for elem := c.order.Front(); elem != nil; {
		next := elem.Next()
		entry := elem.Value.(*Entry[K, V])
		if !entry.ExpiresAt.After(now) {
			c.removeElementLocked(elem)
			removed++
		}
		elem = next
	}
	return removed
}

func (c *TTLLRU[K, V]) setLocked(key K, value V, expiresAt time.Time) {
	if elem, ok := c.entries[key]; ok {
		entry := elem.Value.(*Entry[K, V])
		entry.Value = value
		entry.ExpiresAt = expiresAt
		c.order.MoveToBack(elem)
		return
	}
	for len(c.entries) >= c.maxEntries {
		elem := c.order.Front()
		if elem == nil {
			break
		}
		c.removeElementLocked(elem)
	}
	c.entries[key] = c.order.PushBack(&Entry[K, V]{Key: key, Value: value, ExpiresAt: expiresAt})
}

func (c *TTLLRU[K, V]) removeElementLocked(elem *list.Element) {
	entry := elem.Value.(*Entry[K, V])
	delete(c.entries, entry.Key)
	c.order.Remove(elem)
}
