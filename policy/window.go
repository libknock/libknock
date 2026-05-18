package policy

import "time"

type Clock interface{ Now() time.Time }
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type Window struct {
	Limit int
	Every time.Duration
}

func (w Window) WithDefaults() Window {
	if w.Limit <= 0 {
		w.Limit = 1
	}
	if w.Every <= 0 {
		w.Every = time.Second
	}
	return w
}
