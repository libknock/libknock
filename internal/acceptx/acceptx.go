// Package acceptx holds helpers shared by accept loops.
package acceptx

import (
	"errors"
	"net"
	"syscall"
	"time"
)

const (
	minBackoff = 5 * time.Millisecond
	maxBackoff = time.Second
)

// IsTemporary reports whether an Accept error is transient, such as file
// descriptor exhaustion or a connection aborted before Accept returned. Accept
// loops should back off and retry on these errors instead of shutting down;
// otherwise a burst of connections that exhausts descriptors permanently
// disables the listener.
func IsTemporary(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ENOMEM) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.ECONNRESET)
}

// Backoff tracks the retry delay for consecutive temporary Accept errors.
type Backoff struct{ delay time.Duration }

// Next returns the next delay, doubling from 5ms up to 1s.
func (b *Backoff) Next() time.Duration {
	if b.delay == 0 {
		b.delay = minBackoff
	} else {
		b.delay *= 2
	}
	if b.delay > maxBackoff {
		b.delay = maxBackoff
	}
	return b.delay
}

// Reset clears the delay after a successful Accept.
func (b *Backoff) Reset() { b.delay = 0 }

// Sleep waits for d or until done is closed. It reports false when done fired.
func Sleep(d time.Duration, done <-chan struct{}) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-done:
		return false
	}
}
