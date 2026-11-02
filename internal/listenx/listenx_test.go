package listenx

import (
	"context"
	"net"
	"testing"
	"time"
)

func acceptedMPTCP(t *testing.T, mptcp bool) bool {
	t.Helper()
	ln, err := ListenTCP(context.Background(), "127.0.0.1:0", mptcp)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- nil
			return
		}
		done <- c
	}()
	var d net.Dialer
	d.SetMultipathTCP(true) // a client that asks for MPTCP
	cc, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	select {
	case c := <-done:
		if c == nil {
			t.Fatal("accept failed")
		}
		defer c.Close()
		used, err := c.(*net.TCPConn).MultipathTCP()
		if err != nil {
			t.Fatal(err)
		}
		return used
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
	}
	return false
}

// TestListenTCPDisablesMPTCP checks that an MPTCP-capable client falls back to
// plain TCP when the listener is created with mptcp=false, even under the Go
// 1.24+ default (multipathtcp=2).
func TestListenTCPDisablesMPTCP(t *testing.T) {
	if acceptedMPTCP(t, false) {
		t.Fatal("listener with mptcp=false accepted an MPTCP connection")
	}
}

// TestListenTCPHonoursOptIn only asserts when the kernel supports MPTCP.
func TestListenTCPHonoursOptIn(t *testing.T) {
	if !acceptedMPTCP(t, true) {
		t.Skip("MPTCP not available on this host")
	}
}
