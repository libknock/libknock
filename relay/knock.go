package relay

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/firewall"
	"github.com/libknock/libknock/internal/gatewaycore"
	"github.com/libknock/libknock/internal/timerset"
	"github.com/libknock/libknock/knock"
)

func (g *Gateway) listenKnock(ctx context.Context, fw firewall.Backend, store *KnockSessionStore, protectedPort int, timers *timerset.Set) error {
	if err := knock.ValidateClientSecrets(g.KnockClients); err != nil {
		return err
	}
	if err := knock.ValidateRelayServerMethod(g.KnockMethod); err != nil {
		return err
	}
	handler := func(ev knock.Event) {
		remote, ok := netip.AddrFromSlice(ev.SourceIP)
		if !ok {
			g.emitKnockFail(KnockFailEvent{ClientID: ev.ClientID, Reason: "invalid_source_ip"})
			return
		}
		ttl := g.AllowTTL
		if ttl <= 0 {
			ttl = time.Minute
		}
		port := protectedPort
		if err := gatewaycore.AllowFirewall(ctx, fw, remote, port, ttl, g.Events); err != nil {
			g.emitKnockFail(KnockFailEvent{Remote: remote, ClientID: ev.ClientID, Reason: "firewall_allow_failed", Err: err})
			return
		}
		uses := g.MaxConnectionsPerKnock
		leaseID, ok := store.MarkFirewall(remote, port, ttl)
		if !ok {
			if gatewaycore.ShouldManualRevoke(fw) {
				_ = gatewaycore.RevokeFirewall(ctx, fw, remote, port, g.Events)
			}
			g.emitKnockFail(KnockFailEvent{Remote: remote, ClientID: ev.ClientID, Reason: "firewall_lease_store_full"})
			return
		}
		store.AddSessionForPort(remote, ev.ClientID, ev.SessionID, port, ttl, uses)
		g.emitKnockOK(KnockEvent{Remote: remote, ClientID: ev.ClientID, Method: ev.Method, Parts: ev.Parts, TTL: ttl})
		timers.AfterFunc(ttl, func() {
			store.Expire(remote, ev.ClientID, time.Now())
			if store.ExpireFirewall(remote, port, leaseID, time.Now()) && gatewaycore.ShouldManualRevoke(fw) {
				gatewaycore.RevokeFirewall(ctx, fw, remote, port, g.Events)
			}
		})
	}
	opts := knock.ListenOptions{Port: protectedPort, KnockPort: g.KnockPort, Clients: g.KnockClients, TimeWindow: g.KnockTimeWindow, MaxFrameSize: g.KnockMaxFrameSize, RequireSessionID: !g.DisableSessionBinding, ReplayCache: auth.NewMemoryReplayCache(5 * time.Minute), Sequence: g.KnockSequence, NonceTTL: g.KnockNonceTTL}
	switch knock.NormalizeMethod(g.KnockMethod) {
	case knock.TCPSYNMethod:
		return knock.Listen(ctx, opts, handler)
	case knock.UDPMethod:
		return knock.ListenUDP(ctx, gatewaycore.DefaultString(g.KnockListen, gatewaycore.UDPListenStringForKnockPort(g.Listen, g.KnockPort)), opts, handler)
	case knock.UDPSeqMethod:
		return knock.ListenUDPSequence(ctx, gatewaycore.DefaultString(g.KnockListen, gatewaycore.UDPListenStringForKnockPort(g.Listen, g.KnockPort)), opts, handler)
	case knock.UDPPassiveMethod:
		return knock.ListenUDPPassive(ctx, opts, handler)
	case knock.UDPPassiveSeq:
		return knock.ListenUDPPassiveSequence(ctx, opts, handler)
	case knock.TCP_SYNSeqMethod:
		return knock.ListenSYNSequence(ctx, opts, handler)
	default:
		return fmt.Errorf("unsupported knock method %q", g.KnockMethod)
	}
}
