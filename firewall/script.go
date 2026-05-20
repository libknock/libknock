package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
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

func (s *Script) Validate() error {
	if s.cfg.Script.AllowCmd == "" || s.cfg.Script.RevokeCmd == "" || s.cfg.Script.CleanupCmd == "" {
		return errors.New("firewall backend script requires allow_cmd, revoke_cmd, and cleanup_cmd")
	}
	if s.cfg.Runner != nil {
		return nil
	}
	for _, cmd := range []string{s.cfg.Script.AllowCmd, s.cfg.Script.RevokeCmd, s.cfg.Script.CleanupCmd} {
		if _, err := exec.LookPath(cmd); err != nil {
			return fmt.Errorf("firewall backend script command %q was not found: %w", cmd, err)
		}
	}
	return nil
}

func (s *Script) Init(ctx context.Context) error { return s.Validate() }

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
