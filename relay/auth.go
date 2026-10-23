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
	session := g.authenticateConn(parent, conn, cfg, fw, store)
	if session == nil {
		return
	}
	g.relaySession(parent, session)
}

// authenticatedSession is a connection that passed TCP auth and is ready to be
// relayed. Splitting auth from relaying lets the bounded auth worker pool
// return to the queue as soon as authentication finishes, instead of being
// pinned for the lifetime of a relayed session.
type authenticatedSession struct {
	raw    net.Conn
	client net.Conn
	peer   *auth.PeerInfo
	start  time.Time
}

// authenticateConn runs the bounded auth phase. On failure it closes conn and
// returns nil; on success the caller owns the returned session and must pass
// it to relaySession.
func (g *Gateway) authenticateConn(parent context.Context, conn net.Conn, cfg auth.ServerConfig, fw firewall.Backend, store *KnockSessionStore) *authenticatedSession {
	start := time.Now()
	ctx, cancel := context.WithTimeout(parent, nonzero(g.Auth.AuthTimeout, auth.DefaultAuthTimeout))
	defer cancel()
	client, peer, err := auth.ServerAuth(ctx, conn, cfg)
	if err != nil {
		_ = conn.Close()
		g.emitRelayError(RelayErrorEvent{Remote: conn.RemoteAddr(), Stage: "auth", Err: err})
		return nil
	}
	if g.RemoveAfterAuth {
		port := cfg.ServerPort
		if port <= 0 {
			port = gatewaycore.ListenerPort(conn.LocalAddr())
		}
		g.removeKnockAccess(conn.RemoteAddr(), peer.ClientID, port, fw, store)
	}
	return &authenticatedSession{raw: conn, client: client, peer: peer, start: start}
}

func (g *Gateway) relaySession(parent context.Context, s *authenticatedSession) {
	conn := s.raw
	defer conn.Close()
	defer s.client.Close()
	dialer := net.Dialer{Timeout: nonzero(g.UpstreamConnectTimeout, 5*time.Second)}
	upstream, err := dialer.DialContext(parent, "tcp", g.Upstream)
	if err != nil {
		g.emitRelayError(RelayErrorEvent{Remote: conn.RemoteAddr(), ClientID: s.peer.ClientID, Stage: "upstream", Err: err})
		return
	}
	defer upstream.Close()
	stats, err := bidirectionalContext(parent, s.client, upstream, g.IdleTimeout)
	if err != nil {
		g.emitRelayError(RelayErrorEvent{Remote: conn.RemoteAddr(), ClientID: s.peer.ClientID, Stage: "relay", Err: err})
		return
	}
	g.emitRelayOK(RelayEvent{Remote: conn.RemoteAddr(), ClientID: s.peer.ClientID, RX: stats.RX, TX: stats.TX, Duration: time.Since(s.start)})
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
