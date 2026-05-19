package netx

import (
	"context"
	"crypto/rand"
	"net"

	"github.com/libknock/libknock/auth"
)

type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Dialer struct {
	Base   ContextDialer
	Config auth.ClientConfig
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg := d.Config.WithDefaults()
	if err := cfg.ValidateRuntime(); err != nil {
		return nil, err
	}
	if cfg.Knock != nil {
		if len(cfg.SessionID) == 0 {
			cfg.SessionID = make([]byte, 16)
			if _, err := rand.Read(cfg.SessionID); err != nil {
				return nil, err
			}
		}
		if setter, ok := cfg.Knock.(auth.SessionBoundKnockSender); ok {
			setter.SetSessionID(cfg.SessionID)
		}
		if err := cfg.Knock.Knock(ctx); err != nil {
			return nil, err
		}
	}
	base := d.Base
	if base == nil {
		base = &net.Dialer{}
	}
	conn, err := base.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if err := auth.ClientAuth(ctx, conn, cfg); err != nil {
		return nil, err
	}
	return conn, nil
}
