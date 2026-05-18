package timerset

import (
	"sync"
	"time"
)

type Set struct {
	mu     sync.Mutex
	wg     sync.WaitGroup
	timers map[*time.Timer]*timerEntry
}

type timerEntry struct {
	done sync.Once
}

func New() *Set { return &Set{timers: make(map[*time.Timer]*timerEntry)} }

func (s *Set) AfterFunc(d time.Duration, f func()) *time.Timer {
	if s == nil {
		return time.AfterFunc(d, f)
	}
	entry := &timerEntry{}
	s.wg.Add(1)
	var t *time.Timer
	s.mu.Lock()
	t = time.AfterFunc(d, func() {
		defer entry.done.Do(s.wg.Done)
		s.mu.Lock()
		delete(s.timers, t)
		s.mu.Unlock()
		f()
	})
	if s.timers == nil {
		s.timers = make(map[*time.Timer]*timerEntry)
	}
	s.timers[t] = entry
	s.mu.Unlock()
	return t
}

func (s *Set) StopAll() {
	if s == nil {
		return
	}
	s.mu.Lock()
	timers := s.timers
	s.timers = make(map[*time.Timer]*timerEntry)
	s.mu.Unlock()
	for t, entry := range timers {
		if t.Stop() {
			entry.done.Do(s.wg.Done)
		}
	}
	s.wg.Wait()
}
