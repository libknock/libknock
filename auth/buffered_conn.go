package auth

import (
	"bufio"
	"context"
	"net"
)

type peerContextKey struct{}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

// Read serves bytes already pulled by authentication before returning to the underlying connection. This preserves a clean application stream even when the auth parser has buffered beyond the auth frame.
func (c *bufferedConn) Read(p []byte) (int, error) {
	if c.r != nil {
		return c.r.Read(p)
	}
	return c.Conn.Read(p)
}

type authenticatedConn struct {
	*bufferedConn
	peer PeerInfo
}

func (c *authenticatedConn) PeerInfo() PeerInfo {
	if c == nil {
		return PeerInfo{}
	}
	return clonePeer(c.peer)
}

func PeerFromConn(conn net.Conn) (PeerInfo, bool) {
	if conn == nil {
		return PeerInfo{}, false
	}
	if c, ok := conn.(PeerInfoProvider); ok {
		return c.PeerInfo(), true
	}
	return PeerInfo{}, false
}

func ContextWithPeer(ctx context.Context, peer PeerInfo) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, peerContextKey{}, clonePeer(peer))
}

func PeerFromContext(ctx context.Context) (PeerInfo, bool) {
	if ctx == nil {
		return PeerInfo{}, false
	}
	peer, ok := ctx.Value(peerContextKey{}).(PeerInfo)
	if !ok {
		return PeerInfo{}, false
	}
	return clonePeer(peer), true
}

func ConnContextWithPeer(ctx context.Context, conn net.Conn) context.Context {
	if peer, ok := PeerFromConn(conn); ok {
		return ContextWithPeer(ctx, peer)
	}
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func clonePeer(peer PeerInfo) PeerInfo {
	peer.Nonce = append([]byte(nil), peer.Nonce...)
	peer.SessionID = append([]byte(nil), peer.SessionID...)
	peer.Extensions = append([]byte(nil), peer.Extensions...)
	return peer
}
