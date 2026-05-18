package gatewaycore

import (
	"context"
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

func CleanupFirewall(ctx context.Context, fw firewall.Backend) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), FirewallOperationTimeout)
	defer cancel()
	if ctx != nil && ctx.Err() != nil {
		return fw.Cleanup(cleanupCtx)
	}
	return fw.Cleanup(cleanupCtx)
}

func InitFirewall(ctx context.Context, fw firewall.Backend) error {
	if err := fw.Init(ctx); err != nil {
		return fmt.Errorf("initialize firewall backend %s: %w", fw.Name(), err)
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

func RevokeFirewall(ctx context.Context, fw firewall.Backend, remote netip.Addr, port int, sink observability.GatewayEvents) {
	revokeCtx, cancel := FirewallOpContext(ctx)
	defer cancel()
	if err := fw.Revoke(revokeCtx, remote, port); err != nil {
		EventEmitter{Sink: sink}.FirewallError(observability.FirewallErrorEvent{Remote: remote, Port: port, Err: err})
	}
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
