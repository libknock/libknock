package gate

import (
	"errors"
	"net"
	"net/netip"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/internal/gatewaycore"
	"github.com/libknock/libknock/observability"
)

type firewallOnlyListener struct {
	net.Listener
	store  relayStore
	events observability.GatewayEvents
}

type relayStore interface {
	CheckAndConsume(peer auth.PeerInfo, remote net.Addr) error
}

func (l *firewallOnlyListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		remote, ok := gatewaycore.AddrFromNet(conn.RemoteAddr())
		if !ok {
			_ = conn.Close()
			continue
		}
		if err := l.store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: firewallOnlyClientID, ClientIDHash: addrHash(remote)}}, conn.RemoteAddr()); err != nil {
			if l.events != nil {
				l.events.OnRelayError(observability.RelayErrorEvent{Remote: conn.RemoteAddr(), Stage: "knock", Err: errors.Join(auth.ErrKnockRequired, err)})
			}
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}

const firewallOnlyClientID = "*"

func addrHash(addr netip.Addr) [16]byte { return addr.As16() }
