package relay

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

func Bidirectional(a, b net.Conn, idleTimeout time.Duration) Stats {
	var rx, tx atomic.Int64
	var wg sync.WaitGroup
	wg.Add(2)
	go copyHalf(&wg, a, b, &rx, idleTimeout)
	go copyHalf(&wg, b, a, &tx, idleTimeout)
	wg.Wait()
	return Stats{RX: rx.Load(), TX: tx.Load()}
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
func copyHalf(wg *sync.WaitGroup, dst, src net.Conn, counter *atomic.Int64, idleTimeout time.Duration) {
	defer wg.Done()
	if idleTimeout > 0 {
		_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
	}
	_, _ = io.Copy(countingWriter{w: dst, n: counter}, deadlineReader{Conn: src, timeout: idleTimeout})
	closeWrite(dst)
	closeRead(src)
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
