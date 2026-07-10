package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type pipeTestConn struct {
	closed     atomic.Bool
	readClosed atomic.Bool
}

func (c *pipeTestConn) Read([]byte) (int, error)         { return 0, nil }
func (c *pipeTestConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *pipeTestConn) Close() error                     { c.closed.Store(true); return nil }
func (c *pipeTestConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *pipeTestConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *pipeTestConn) SetDeadline(time.Time) error      { return nil }
func (c *pipeTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipeTestConn) SetWriteDeadline(time.Time) error { return nil }

type pipeReadCloserConn struct{ pipeTestConn }

func (c *pipeReadCloserConn) CloseRead() error { c.readClosed.Store(true); return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

func TestCloseReadUsesHalfCloseWhenSupported(t *testing.T) {
	conn := &pipeReadCloserConn{}
	closeRead(conn)
	if !conn.readClosed.Load() {
		t.Fatal("CloseRead was not called")
	}
	if conn.closed.Load() {
		t.Fatal("Close should not be called when CloseRead is supported")
	}
}

func TestCloseReadFallsBackToClose(t *testing.T) {
	conn := &pipeTestConn{}
	closeRead(conn)
	if !conn.closed.Load() {
		t.Fatal("Close was not called for conn without CloseRead")
	}
}

type copyErrorConn struct {
	pipeTestConn
	err error
}

func (c *copyErrorConn) Read([]byte) (int, error) { return 0, c.err }

func TestBidirectionalContextReturnsUnexpectedCopyError(t *testing.T) {
	want := errors.New("injected copy failure")
	stats, err := BidirectionalContext(context.Background(), &copyErrorConn{err: want}, &copyErrorConn{err: io.EOF}, 0)
	if !errors.Is(err, want) {
		t.Fatalf("BidirectionalContext err = %v, want %v", err, want)
	}
	if stats.RX != 0 || stats.TX != 0 {
		t.Fatalf("stats = %+v, want zero", stats)
	}
}

func TestRelayCopyErrorIgnoresExpectedCloseErrors(t *testing.T) {
	if err := relayCopyError(io.EOF, net.ErrClosed); err != nil {
		t.Fatalf("relayCopyError = %v, want nil", err)
	}
}
