package gatewaycore

import (
	"net"
	"testing"
	"time"
)

func TestAddrFromIPUnmapsIPv4MappedIPv6(t *testing.T) {
	// Dual-stack UDP sockets report IPv4 peers as ::ffff:a.b.c.d. Knock
	// sessions must use the same canonical form as the TCP side.
	got, ok := AddrFromIP(net.ParseIP("::ffff:192.0.2.10"))
	if !ok {
		t.Fatal("AddrFromIP rejected mapped address")
	}
	tcp, ok := AddrFromNet(&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22})
	if !ok {
		t.Fatal("AddrFromNet rejected address")
	}
	if got != tcp || !got.Is4() {
		t.Fatalf("AddrFromIP = %v, AddrFromNet = %v; want equal IPv4", got, tcp)
	}
	if _, ok := AddrFromIP(nil); ok {
		t.Fatal("AddrFromIP accepted nil IP")
	}
	v6, ok := AddrFromIP(net.ParseIP("2001:db8::1"))
	if !ok || !v6.Is6() {
		t.Fatalf("AddrFromIP(IPv6) = %v, %v", v6, ok)
	}
}

func TestAddrFromNetUnmapsStringAddrs(t *testing.T) {
	got, ok := AddrFromNet(&net.UDPAddr{IP: net.ParseIP("::ffff:198.51.100.7"), Port: 1})
	if !ok || got.String() != "198.51.100.7" {
		t.Fatalf("AddrFromNet = %v, %v", got, ok)
	}
}

func TestKnockReplayTTLCoversAcceptanceWindow(t *testing.T) {
	if got := KnockReplayTTL(30 * time.Second); got != DefaultKnockReplayTTL {
		t.Fatalf("default window TTL = %v", got)
	}
	for _, w := range []time.Duration{3 * time.Minute, 10 * time.Minute} {
		if got := KnockReplayTTL(w); got <= 2*w {
			t.Fatalf("KnockReplayTTL(%v) = %v, must exceed 2*window", w, got)
		}
	}
	if got := KnockReplayTTL(0); got != DefaultKnockReplayTTL {
		t.Fatalf("zero window TTL = %v", got)
	}
}
