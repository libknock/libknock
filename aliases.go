package libknock

import (
	"context"
	"net"
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/netx"
)

type ServerConfig = auth.ServerConfig
type ClientConfig = auth.ClientConfig
type PeerInfo = auth.PeerInfo
type Server = auth.Server
type Dialer = netx.Dialer

func NewStaticSecretResolver(secrets map[string][]byte) auth.StaticSecrets {
	return auth.NewStaticSecretResolver(secrets)
}
func NewMemoryReplayCache(ttl time.Duration) *auth.MemoryReplayCache {
	return auth.NewMemoryReplayCache(ttl)
}
func WrapListener(ln net.Listener, cfg ServerConfig) net.Listener { return netx.WrapListener(ln, cfg) }
func NewServer(cfg ServerConfig) (*Server, error)                 { return auth.NewServer(cfg) }
func ServerAuth(ctx context.Context, conn net.Conn, cfg ServerConfig) (net.Conn, *PeerInfo, error) {
	return auth.ServerAuth(ctx, conn, cfg)
}
func ClientAuth(ctx context.Context, conn net.Conn, cfg ClientConfig) error {
	return auth.ClientAuth(ctx, conn, cfg)
}
