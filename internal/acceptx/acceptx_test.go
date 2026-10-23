package acceptx

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestIsTemporary(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{net.ErrClosed, false},
		{fmt.Errorf("wrapped: %w", net.ErrClosed), false},
		{&net.OpError{Op: "accept", Err: os.NewSyscallError("accept", syscall.EMFILE)}, true},
		{&net.OpError{Op: "accept", Err: os.NewSyscallError("accept", syscall.ECONNABORTED)}, true},
		{errors.New("permanent"), false},
	}
	for _, tc := range cases {
		if got := IsTemporary(tc.err); got != tc.want {
			t.Fatalf("IsTemporary(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestBackoff(t *testing.T) {
	var b Backoff
	if d := b.Next(); d != minBackoff {
		t.Fatalf("first delay = %v", d)
	}
	for i := 0; i < 20; i++ {
		b.Next()
	}
	if d := b.Next(); d != maxBackoff {
		t.Fatalf("capped delay = %v", d)
	}
	b.Reset()
	if d := b.Next(); d != minBackoff {
		t.Fatalf("delay after reset = %v", d)
	}
}

func TestSleepStopsOnDone(t *testing.T) {
	done := make(chan struct{})
	close(done)
	start := time.Now()
	if Sleep(time.Hour, done) {
		t.Fatal("Sleep returned true after done closed")
	}
	if time.Since(start) > time.Second {
		t.Fatal("Sleep did not return promptly")
	}
}
