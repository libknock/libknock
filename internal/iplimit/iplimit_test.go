package iplimit

import (
	"net"
	"testing"
)

func TestKeyAggregatesIPv6To64AndUnmapsIPv4(t *testing.T) {
	cases := []struct {
		addr net.Addr
		want string
	}{
		{&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}, "192.0.2.1"},
		{&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 1}, "192.0.2.1"},
		{&net.UDPAddr{IP: net.ParseIP("2001:db8:1:2:aaaa::1"), Port: 1}, "2001:db8:1:2::/64"},
		{&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:ffff::9"), Port: 1}, "2001:db8:1:2::/64"},
	}
	for _, tc := range cases {
		got, ok := Key(tc.addr)
		if !ok || got != tc.want {
			t.Fatalf("Key(%v) = %q,%v want %q", tc.addr, got, ok, tc.want)
		}
	}
	if _, ok := Key(nil); ok {
		t.Fatal("nil addr should not produce a key")
	}
}

func TestLimiterCapsPerSource(t *testing.T) {
	l := New(2)
	a := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1}
	b := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 2} // same /64
	c := &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 3}
	r1, ok := l.Acquire(a)
	if !ok {
		t.Fatal("first acquire failed")
	}
	r2, ok := l.Acquire(b)
	if !ok {
		t.Fatal("second acquire failed")
	}
	if _, ok := l.Acquire(a); ok {
		t.Fatal("third acquire in same /64 should be rejected")
	}
	if _, ok := l.Acquire(c); !ok {
		t.Fatal("other source should not be limited")
	}
	r1()
	r1() // idempotent
	if _, ok := l.Acquire(a); !ok {
		t.Fatal("acquire after release failed")
	}
	r2()
	var nilL *Limiter
	if _, ok := nilL.Acquire(a); !ok {
		t.Fatal("nil limiter must not limit")
	}
	if New(0) != nil {
		t.Fatal("New(0) should disable")
	}
}
