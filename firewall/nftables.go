package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

type Nftables struct {
	name   string
	cfg    Config
	family string
	table  string
	chain  string
	setV4  string
	setV6  string
}

func NewNftables(cfg Config, name string) *Nftables {
	cfg = cfg.WithDefaults()
	family := cfg.Nftables.Family
	if family == "" {
		family = "inet"
	}
	table := cfg.Nftables.Table
	if table == "" {
		table = "knock_gateway"
	}
	chain := cfg.Nftables.Chain
	if chain == "" {
		chain = "input"
	}
	setV4 := cfg.Nftables.SetV4
	if setV4 == "" {
		setV4 = "allowed_clients_v4"
	}
	setV6 := cfg.Nftables.SetV6
	if setV6 == "" {
		setV6 = "allowed_clients_v6"
	}
	return &Nftables{name: name, cfg: cfg, family: family, table: table, chain: chain, setV4: setV4, setV6: setV6}
}

func (n *Nftables) Name() string {
	if n.name == "" {
		return "nftables"
	}
	return n.name
}

func (n *Nftables) Config() Config { return n.cfg }
func (n *Nftables) WithConfig(cfg Config) (Backend, error) {
	if err := validateFirewallPort(cfg.Port, n.Name()); err != nil {
		return nil, err
	}
	if err := validateNftablesConfig(cfg.Nftables); err != nil {
		return nil, err
	}
	return NewNftables(cfg, n.name), nil
}

func (n *Nftables) Init(ctx context.Context) error {
	if err := validateNftablesConfig(n.cfg.Nftables); err != nil {
		return err
	}
	ipv6 := ipv6Enabled(n.cfg, n.Name())
	udpDropRule := ""
	if n.cfg.DropUDPKnockPort {
		udpDropRule = fmt.Sprintf("    udp dport %d drop\n", udpKnockPort(n.cfg))
	}
	setV6, ruleV6 := "", ""
	if ipv6 {
		setV6 = fmt.Sprintf("\n  set %s {\n    type ipv6_addr\n    timeout %ds\n  }\n", n.setV6, int(n.cfg.AllowSeconds))
		ruleV6 = fmt.Sprintf("    ip6 saddr @%s tcp dport %d accept\n", n.setV6, n.cfg.Port)
	}
	createScript := fmt.Sprintf(`table %s %s {
  set %s {
    type ipv4_addr
    timeout %ds
  }
%s

  chain %s {
    type filter hook input priority -10; policy accept;
    ct state established,related accept
    ip saddr @%s tcp dport %d accept
%s
    tcp dport %d drop
%s
  }
}
`, n.family, n.table, n.setV4, int(n.cfg.AllowSeconds), setV6, n.chain, n.setV4, n.cfg.Port, ruleV6, n.cfg.Port, udpDropRule)

	if err := n.Cleanup(ctx); err != nil {
		return err
	}
	if err := runInputWithConfig(ctx, n.cfg, createScript, "nft", "-f", "-"); err != nil {
		cleanupErr := n.cleanupDetached()
		return errors.Join(err, cleanupErr)
	}
	return nil
}

func (n *Nftables) Allow(ctx context.Context, addr netip.Addr, port int, ttl time.Duration) error {
	if err := validateBoundFirewallPort(n.Name(), n.cfg.Port, port); err != nil {
		return err
	}
	if ttl <= 0 {
		return fmt.Errorf("nftables allow ttl must be greater than zero")
	}
	seconds, err := ttlSeconds(ttl)
	if err != nil {
		return err
	}
	v4 := toIP(addr).To4()
	if v4 == nil {
		if toIP(addr).To16() == nil {
			return fmt.Errorf("invalid IP address %s", addr.String())
		}
		if !ipv6Enabled(n.cfg, n.Name()) {
			return errIPv6Unsupported(n.Name())
		}
		deleteInput := fmt.Sprintf("delete element %s %s %s { %s }\n", n.family, n.table, n.setV6, addr.String())
		_ = ignoreMissingFirewallObject(runInputWithConfig(ctx, n.cfg, deleteInput, "nft", "-f", "-"))
		input := fmt.Sprintf("add element %s %s %s { %s timeout %ds }\n", n.family, n.table, n.setV6, addr.String(), seconds)
		return runInputWithConfig(ctx, n.cfg, input, "nft", "-f", "-")
	}
	deleteInput := fmt.Sprintf("delete element %s %s %s { %s }\n", n.family, n.table, n.setV4, v4.String())
	_ = ignoreMissingFirewallObject(runInputWithConfig(ctx, n.cfg, deleteInput, "nft", "-f", "-"))
	input := fmt.Sprintf("add element %s %s %s { %s timeout %ds }\n", n.family, n.table, n.setV4, v4.String(), seconds)
	return runInputWithConfig(ctx, n.cfg, input, "nft", "-f", "-")
}

func (n *Nftables) IsAllowed(ctx context.Context, addr netip.Addr, port int) (bool, error) {
	if err := validateBoundFirewallPort(n.Name(), n.cfg.Port, port); err != nil {
		return false, err
	}
	ip := toIP(addr)
	v4 := ip.To4()
	set := n.setV4
	addrText := addr.String()
	if v4 == nil {
		if ip.To16() == nil {
			return false, fmt.Errorf("invalid IP address %s", addr.String())
		}
		if !ipv6Enabled(n.cfg, n.Name()) {
			return false, nil
		}
		set = n.setV6
	} else {
		addrText = v4.String()
	}
	if err := runWithConfig(ctx, n.cfg, "nft", "get", "element", n.family, n.table, set, "{", addrText, "}"); err != nil {
		if isMissingFirewallObject(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (n *Nftables) Revoke(ctx context.Context, addr netip.Addr, port int) error {
	if err := validateBoundFirewallPort(n.Name(), n.cfg.Port, port); err != nil {
		return err
	}
	v4 := toIP(addr).To4()
	if v4 == nil {
		if toIP(addr).To16() == nil {
			return nil
		}
		if !ipv6Enabled(n.cfg, n.Name()) {
			return nil
		}
		input := fmt.Sprintf("delete element %s %s %s { %s }\n", n.family, n.table, n.setV6, addr.String())
		return ignoreMissingFirewallObject(runInputWithConfig(ctx, n.cfg, input, "nft", "-f", "-"))
	}
	input := fmt.Sprintf("delete element %s %s %s { %s }\n", n.family, n.table, n.setV4, v4.String())
	return ignoreMissingFirewallObject(runInputWithConfig(ctx, n.cfg, input, "nft", "-f", "-"))
}

func (n *Nftables) Cleanup(ctx context.Context) error {
	if err := validateNftablesConfig(n.cfg.Nftables); err != nil {
		return err
	}
	return ignoreMissingFirewallObject(runInputWithConfig(ctx, n.cfg, fmt.Sprintf("delete table %s %s\n", n.family, n.table), "nft", "-f", "-"))
}

func (n *Nftables) cleanupDetached() error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), defaultCommandTimeout)
	defer cancel()
	return n.Cleanup(cleanupCtx)
}
