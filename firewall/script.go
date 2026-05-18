package firewall

import (
	"context"
	"net/netip"
	"strconv"
	"time"
)

type Script struct {
	cfg Config
}

func NewScript(cfg Config) *Script {
	return &Script{cfg: cfg}
}

func (s *Script) Name() string { return "script" }

func (s *Script) Config() Config { return s.cfg }
func (s *Script) WithConfig(cfg Config) (Backend, error) {
	if err := validateFirewallPort(cfg.Port, s.Name()); err != nil {
		return nil, err
	}
	return NewScript(cfg), nil
}

func (s *Script) Init(ctx context.Context) error {
	return nil
}

func (s *Script) Allow(ctx context.Context, addr netip.Addr, port int, ttl time.Duration) error {
	if err := validateBoundFirewallPort(s.Name(), s.cfg.Port, port); err != nil {
		return err
	}
	seconds, err := ttlSeconds(ttl)
	if err != nil {
		return err
	}
	return runWithConfig(ctx, s.cfg, s.cfg.Script.AllowCmd, addr.String(), strconv.Itoa(port), strconv.Itoa(seconds))
}

func (s *Script) Revoke(ctx context.Context, addr netip.Addr, port int) error {
	if err := validateBoundFirewallPort(s.Name(), s.cfg.Port, port); err != nil {
		return err
	}
	return runWithConfig(ctx, s.cfg, s.cfg.Script.RevokeCmd, addr.String(), strconv.Itoa(port))
}

func (s *Script) Cleanup(ctx context.Context) error {
	return runWithConfig(ctx, s.cfg, s.cfg.Script.CleanupCmd, strconv.Itoa(s.cfg.Port))
}
