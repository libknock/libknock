package relay

import (
	"context"
	"net"
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/firewall"
	"github.com/libknock/libknock/internal/gatewaycore"
)

var bidirectionalContext = BidirectionalContext

func (g *Gateway) handleConn(parent context.Context, conn net.Conn, cfg auth.ServerConfig, fw firewall.Backend, store *KnockSessionStore) {
	defer conn.Close()
	start := time.Now()
	ctx, cancel := context.WithTimeout(parent, nonzero(g.Auth.AuthTimeout, auth.DefaultAuthTimeout))
	defer cancel()
	client, peer, err := auth.ServerAuth(ctx, conn, cfg)
	if err != nil {
		g.emitRelayError(RelayErrorEvent{Remote: conn.RemoteAddr(), Stage: "auth", Err: err})
		return
	}
	if g.RemoveAfterAuth {
		port := cfg.ServerPort
		if port <= 0 {
			port = gatewaycore.ListenerPort(conn.LocalAddr())
		}
		g.removeKnockAccess(conn.RemoteAddr(), peer.ClientID, port, fw, store)
	}
	defer client.Close()
	dialer := net.Dialer{Timeout: nonzero(g.UpstreamConnectTimeout, 5*time.Second)}
	upstream, err := dialer.DialContext(parent, "tcp", g.Upstream)
	if err != nil {
		g.emitRelayError(RelayErrorEvent{Remote: conn.RemoteAddr(), ClientID: peer.ClientID, Stage: "upstream", Err: err})
		return
	}
	defer upstream.Close()
	stats, err := bidirectionalContext(parent, client, upstream, g.IdleTimeout)
	if err != nil {
		g.emitRelayError(RelayErrorEvent{Remote: conn.RemoteAddr(), ClientID: peer.ClientID, Stage: "relay", Err: err})
		return
	}
	g.emitRelayOK(RelayEvent{Remote: conn.RemoteAddr(), ClientID: peer.ClientID, RX: stats.RX, TX: stats.TX, Duration: time.Since(start)})
}

func (g *Gateway) removeKnockAccess(remote net.Addr, clientID string, port int, fw firewall.Backend, store *KnockSessionStore) {
	addr, ok := gatewaycore.AddrFromNet(remote)
	if !ok {
		return
	}
	store.RemoveForPort(addr, clientID, port)
	if port <= 0 {
		port = gatewaycore.ListenerPortFromString(g.Listen)
	}
	store.RemoveFirewall(addr, port)
	revokeCtx, cancel := gatewaycore.FirewallOpContext(context.Background())
	defer cancel()
	if err := fw.Revoke(revokeCtx, addr, port); err != nil {
		g.emitFirewallError(FirewallErrorEvent{Remote: addr, Port: port, Err: err})
	}
}
