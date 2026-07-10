package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"
)

func Bidirectional(a, b net.Conn, idleTimeout time.Duration) Stats {
	stats, _ := BidirectionalContext(context.Background(), a, b, idleTimeout)
	return stats
}

// BidirectionalContext relays both directions until completion or context
// cancellation. EOF and closed-connection errors caused by normal half-close
// or cancellation are not reported as relay failures.
func BidirectionalContext(ctx context.Context, a, b net.Conn, idleTimeout time.Duration) (Stats, error) {
	var rx, tx atomic.Int64
	results := make(chan error, 2)
	go func() { results <- copyHalf(a, b, &rx, idleTimeout) }()
	go func() { results <- copyHalf(b, a, &tx, idleTimeout) }()

	stop := make(chan struct{})
	if ctx != nil {
		go func() {
			select {
			case <-ctx.Done():
				_ = a.Close()
				_ = b.Close()
			case <-stop:
			}
		}()
	}
	errA, errB := <-results, <-results
	close(stop)
	return Stats{RX: rx.Load(), TX: tx.Load()}, relayCopyError(errA, errB)
}

type Stats struct{ RX, TX int64 }

type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (w countingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.n.Add(int64(n))
	return n, err
}
func copyHalf(dst, src net.Conn, counter *atomic.Int64, idleTimeout time.Duration) error {
	if idleTimeout > 0 {
		_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
	}
	_, err := io.Copy(countingWriter{w: dst, n: counter}, deadlineReader{Conn: src, timeout: idleTimeout})
	closeWrite(dst)
	closeRead(src)
	return err
}

func relayCopyError(errs ...error) error {
	var unexpected []error
	for _, err := range errs {
		if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			continue
		}
		unexpected = append(unexpected, err)
	}
	return errors.Join(unexpected...)
}

type deadlineReader struct {
	net.Conn
	timeout time.Duration
}

func (r deadlineReader) Read(p []byte) (int, error) {
	if r.timeout > 0 {
		_ = r.Conn.SetReadDeadline(time.Now().Add(r.timeout))
	}
	return r.Conn.Read(p)
}
func closeWrite(conn net.Conn) {
	if c, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = c.CloseWrite()
		return
	}
	_ = conn.Close()
}
func closeRead(conn net.Conn) {
	if c, ok := conn.(interface{ CloseRead() error }); ok {
		_ = c.CloseRead()
		return
	}
	_ = conn.Close()
}
