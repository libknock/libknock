//go:build linux || darwin

package knock

import (
	"context"
	"sync"

	"golang.org/x/sys/unix"
)

type managedFD struct {
	fd   int
	once sync.Once
	done chan struct{}
}

func newManagedFD(ctx context.Context, fd int) *managedFD {
	m := &managedFD{fd: fd, done: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			m.Close()
		case <-m.done:
		}
	}()
	return m
}

func (m *managedFD) Close() {
	m.once.Do(func() {
		close(m.done)
		_ = unix.Close(m.fd)
	})
}
