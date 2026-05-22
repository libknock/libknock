package observability

import (
	"net"
	"net/netip"
	"time"

	"github.com/libknock/libknock/auth"
)

type AuthEventSink = auth.EventSink

type NetxAuthDropEvent struct {
	Remote  net.Addr
	Reason  error
	Pending int
}

type AuthEvents interface {
	OnAccept(remote net.Addr)
	OnAuthOK(peer auth.PeerInfo)
	OnAuthFail(remote net.Addr, reason error)
	OnAuthDrop(NetxAuthDropEvent)
	OnReplay(remote net.Addr, peerHint uint64)
	OnReplayCacheFull(remote net.Addr, peerHint uint64, length, capacity int)
	OnRateLimited(remote net.Addr)
}

type KnockEvent struct {
	Remote   netip.Addr
	ClientID string
	Method   string
	Parts    int
	TTL      time.Duration
}

type KnockFailEvent struct {
	Remote   netip.Addr
	ClientID string
	Reason   string
	Err      error
}

type FirewallEvent struct {
	Remote netip.Addr
	Port   int
	TTL    time.Duration
}

type FirewallErrorEvent struct {
	Remote netip.Addr
	Port   int
	Err    error
}

type RelayEvent struct {
	Remote   net.Addr
	ClientID string
	RX       int64
	TX       int64
	Duration time.Duration
}

type RelayErrorEvent struct {
	Remote       net.Addr
	ClientID     string
	Stage        string
	Err          error
	DroppedCount int64
	Pending      int
}

type GatewayEvents interface {
	OnKnockOK(KnockEvent)
	OnKnockFail(KnockFailEvent)
	OnFirewallAllow(FirewallEvent)
	OnFirewallError(FirewallErrorEvent)
	OnRelayOK(RelayEvent)
	OnRelayError(RelayErrorEvent)
}

type EventSink interface {
	AuthEvents
	GatewayEvents
}

type Nop struct{}

func (Nop) OnAccept(net.Addr)                            {}
func (Nop) OnAuthOK(auth.PeerInfo)                       {}
func (Nop) OnAuthFail(net.Addr, error)                   {}
func (Nop) OnAuthDrop(NetxAuthDropEvent)                 {}
func (Nop) OnReplay(net.Addr, uint64)                    {}
func (Nop) OnReplayCacheFull(net.Addr, uint64, int, int) {}
func (Nop) OnRateLimited(net.Addr)                       {}
func (Nop) OnKnockOK(KnockEvent)                         {}
func (Nop) OnKnockFail(KnockFailEvent)                   {}
func (Nop) OnFirewallAllow(FirewallEvent)                {}
func (Nop) OnFirewallError(FirewallErrorEvent)           {}
func (Nop) OnRelayOK(RelayEvent)                         {}
func (Nop) OnRelayError(RelayErrorEvent)                 {}
