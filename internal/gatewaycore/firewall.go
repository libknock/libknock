package gatewaycore

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/libknock/libknock/firewall"
	"github.com/libknock/libknock/observability"
)

const FirewallOperationTimeout = 5 * time.Second

func ShouldManualRevoke(fw firewall.Backend) bool { return !firewall.Describe(fw.Name()).Timeout }

func FirewallOpContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, FirewallOperationTimeout)
}

func ConfigureFirewallPort(fw firewall.Backend, port int) (firewall.Backend, error) {
	configured, err := firewall.WithPort(fw, port)
	if err != nil {
		return nil, err
	}
	return configured, nil
}

// CleanupFirewallDetached deliberately ignores parent contexts. Shutdown paths call it after serving contexts may already be cancelled, but firewall state should still get a short best-effort cleanup window.
func CleanupFirewallDetached(fw firewall.Backend) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), FirewallOperationTimeout)
	defer cancel()
	return fw.Cleanup(cleanupCtx)
}

func InitFirewall(ctx context.Context, fw firewall.Backend) error {
	if err := fw.Init(ctx); err != nil {
		cleanupErr := CleanupFirewallDetached(fw)
		return errors.Join(fmt.Errorf("initialize firewall backend %s: %w", fw.Name(), err), cleanupErr)
	}
	return nil
}

func AllowFirewall(ctx context.Context, fw firewall.Backend, remote netip.Addr, port int, ttl time.Duration, sink observability.GatewayEvents) error {
	allowCtx, cancel := FirewallOpContext(ctx)
	defer cancel()
	if err := fw.Allow(allowCtx, remote, port, ttl); err != nil {
		EventEmitter{Sink: sink}.FirewallError(observability.FirewallErrorEvent{Remote: remote, Port: port, Err: err})
		return err
	}
	EventEmitter{Sink: sink}.FirewallAllow(observability.FirewallEvent{Remote: remote, Port: port, TTL: ttl})
	return nil
}

func RevokeFirewall(ctx context.Context, fw firewall.Backend, remote netip.Addr, port int, sink observability.GatewayEvents) error {
	revokeCtx, cancel := FirewallOpContext(ctx)
	defer cancel()
	return revokeFirewall(revokeCtx, fw, remote, port, sink)
}

// RevokeFirewallDetached is for timer and shutdown cleanup after serving
// contexts may already be cancelled.
func RevokeFirewallDetached(fw firewall.Backend, remote netip.Addr, port int, sink observability.GatewayEvents) error {
	revokeCtx, cancel := context.WithTimeout(context.Background(), FirewallOperationTimeout)
	defer cancel()
	return revokeFirewall(revokeCtx, fw, remote, port, sink)
}

func revokeFirewall(ctx context.Context, fw firewall.Backend, remote netip.Addr, port int, sink observability.GatewayEvents) error {
	if err := fw.Revoke(ctx, remote, port); err != nil {
		EventEmitter{Sink: sink}.FirewallError(observability.FirewallErrorEvent{Remote: remote, Port: port, Err: err})
		return err
	}
	return nil
}

func ValidateDropUDPKnockPort(fw firewall.Backend, method string) error {
	cfg, ok := fw.(firewall.ConfigurableBackend)
	if !ok || !cfg.Config().DropUDPKnockPort {
		return nil
	}
	switch method {
	case "udp-passive", "udp-passive-seq":
		return nil
	default:
		return fmt.Errorf("drop_udp_knock_port requires udp-passive knock methods, got %q", method)
	}
}
