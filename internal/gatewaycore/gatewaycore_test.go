package gatewaycore

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/libknock/libknock/firewall"
	"github.com/libknock/libknock/observability"
)

func TestUDPListenForKnockPort(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000}
	if got := UDPListenForKnockPort(addr, 10000); got != "127.0.0.1:10000" {
		t.Fatalf("udp listen = %q", got)
	}
	if got := UDPListenForKnockPort(addr, 0); got != "127.0.0.1:9000" {
		t.Fatalf("udp listen fallback = %q", got)
	}
	if got := UDPListenStringForKnockPort("127.0.0.1:9000", 10000); got != "127.0.0.1:10000" {
		t.Fatalf("udp listen string = %q", got)
	}
}

func TestValidateDropUDPKnockPort(t *testing.T) {
	fw := firewall.NewIptables(firewall.Config{DropUDPKnockPort: true})
	if err := ValidateDropUDPKnockPort(fw, "udp"); err == nil {
		t.Fatal("expected active udp method rejection")
	}
	for _, method := range []string{"udp-passive", "udp-passive-seq"} {
		if err := ValidateDropUDPKnockPort(fw, method); err != nil {
			t.Fatalf("%s rejected: %v", method, err)
		}
	}
}

func TestAllowFirewallEmitsEvents(t *testing.T) {
	sink := &eventSink{}
	fw := &stubFirewall{}
	remote := netip.MustParseAddr("192.0.2.10")
	if err := AllowFirewall(context.Background(), fw, remote, 443, time.Second, sink); err != nil {
		t.Fatal(err)
	}
	if fw.allow != 1 || sink.allow != 1 || sink.fwErr != 0 {
		t.Fatalf("allow=%d sink.allow=%d sink.err=%d", fw.allow, sink.allow, sink.fwErr)
	}
	fw.err = errors.New("boom")
	if err := AllowFirewall(context.Background(), fw, remote, 443, time.Second, sink); err == nil {
		t.Fatal("expected allow error")
	}
	if sink.fwErr != 1 {
		t.Fatalf("firewall errors = %d", sink.fwErr)
	}
}

type stubFirewall struct {
	allow int
	err   error
}

func (f *stubFirewall) Name() string               { return "stub" }
func (f *stubFirewall) Init(context.Context) error { return nil }
func (f *stubFirewall) Allow(context.Context, netip.Addr, int, time.Duration) error {
	f.allow++
	return f.err
}
func (f *stubFirewall) Revoke(context.Context, netip.Addr, int) error { return f.err }
func (f *stubFirewall) Cleanup(context.Context) error                 { return nil }

type eventSink struct{ allow, fwErr int }

func (s *eventSink) OnKnockOK(observability.KnockEvent)               {}
func (s *eventSink) OnKnockFail(observability.KnockFailEvent)         {}
func (s *eventSink) OnFirewallAllow(observability.FirewallEvent)      { s.allow++ }
func (s *eventSink) OnFirewallError(observability.FirewallErrorEvent) { s.fwErr++ }
func (s *eventSink) OnRelayOK(observability.RelayEvent)               {}
func (s *eventSink) OnRelayError(observability.RelayErrorEvent)       {}

type stringAddr string

func (a stringAddr) Network() string { return "test" }
func (a stringAddr) String() string  { return string(a) }

func TestAddrFromNet(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr net.Addr
		want string
		ok   bool
	}{
		{"tcp", &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}, "192.0.2.1", true},
		{"string", stringAddr("198.51.100.2:1234"), "198.51.100.2", true},
		{"nil", nil, "", false},
		{"invalid", stringAddr("not-an-addr"), "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := AddrFromNet(tc.addr)
			if ok != tc.ok {
				t.Fatalf("ok=%v want %v", ok, tc.ok)
			}
			if ok && got.String() != tc.want {
				t.Fatalf("addr=%s want %s", got, tc.want)
			}
		})
	}
}
