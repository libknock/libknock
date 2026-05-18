package firewall

import (
	"context"
	"net/netip"
	"strconv"
	"time"
)

type IPSetIptables struct {
	cfg   Config
	set   string
	setV6 string
	chain string
}

func NewIPSetIptables(cfg Config) *IPSetIptables {
	set := cfg.IPSet.Set
	if set == "" {
		set = "knock_gateway_allowed"
	}
	setV6 := cfg.IPSet.SetV6
	if setV6 == "" {
		setV6 = "knock_gateway_allowed_v6"
	}
	chain := cfg.Iptables.Chain
	if chain == "" {
		chain = "KNOCK_GATEWAY"
	}
	return &IPSetIptables{cfg: cfg, set: set, setV6: setV6, chain: chain}
}

func (i *IPSetIptables) Name() string { return "ipset-iptables" }

func (i *IPSetIptables) Config() Config { return i.cfg }
func (i *IPSetIptables) WithConfig(cfg Config) (Backend, error) {
	if err := validateFirewallPort(cfg.Port, i.Name()); err != nil {
		return nil, err
	}
	if err := validateIPSetIptablesConfig(cfg); err != nil {
		return nil, err
	}
	return NewIPSetIptables(cfg), nil
}

func (i *IPSetIptables) Init(ctx context.Context) error {
	port := strconv.Itoa(i.cfg.Port)
	udpPort := strconv.Itoa(udpKnockPort(i.cfg))
	if err := runWithConfig(ctx, i.cfg, "ipset", "create", i.set, "hash:ip", "timeout", strconv.Itoa(i.cfg.AllowSeconds), "-exist"); err != nil {
		return err
	}
	_ = runWithConfig(ctx, i.cfg, "ipset", "flush", i.set)
	i.cleanupCommand(ctx, "iptables", port, udpPort)
	if err := i.initCommand(ctx, "iptables", i.set, port, udpPort); err != nil {
		return err
	}
	if firewallCommandExists(i.cfg, "ip6tables") {
		if err := runWithConfig(ctx, i.cfg, "ipset", "create", i.setV6, "hash:ip", "family", "inet6", "timeout", strconv.Itoa(i.cfg.AllowSeconds), "-exist"); err != nil {
			return err
		}
		_ = runWithConfig(ctx, i.cfg, "ipset", "flush", i.setV6)
		i.cleanupCommand(ctx, "ip6tables", port, udpPort)
		return i.initCommand(ctx, "ip6tables", i.setV6, port, udpPort)
	}
	return nil
}

func (i *IPSetIptables) Allow(ctx context.Context, addr netip.Addr, port int, ttl time.Duration) error {
	if err := validateBoundFirewallPort(i.Name(), i.cfg.Port, port); err != nil {
		return err
	}
	seconds, err := ttlSeconds(ttl)
	if err != nil {
		return err
	}
	set := i.set
	if toIP(addr).To4() == nil {
		if !firewallCommandExists(i.cfg, "ip6tables") {
			return errIPv6Unsupported("ipset-iptables")
		}
		set = i.setV6
	}
	return runWithConfig(ctx, i.cfg, "ipset", "add", set, addr.String(), "timeout", strconv.Itoa(seconds), "-exist")
}

func (i *IPSetIptables) Revoke(ctx context.Context, addr netip.Addr, port int) error {
	if err := validateBoundFirewallPort(i.Name(), i.cfg.Port, port); err != nil {
		return err
	}
	set := i.set
	if toIP(addr).To4() == nil {
		if !firewallCommandExists(i.cfg, "ip6tables") {
			return nil
		}
		set = i.setV6
	}
	return runWithConfig(ctx, i.cfg, "ipset", "del", set, addr.String())
}

func (i *IPSetIptables) Cleanup(ctx context.Context) error {
	port := strconv.Itoa(i.cfg.Port)
	udpPort := strconv.Itoa(udpKnockPort(i.cfg))
	i.cleanupCommand(ctx, "iptables", port, udpPort)
	if firewallCommandExists(i.cfg, "ip6tables") {
		i.cleanupCommand(ctx, "ip6tables", port, udpPort)
		_ = runWithConfig(ctx, i.cfg, "ipset", "flush", i.setV6)
		_ = runWithConfig(ctx, i.cfg, "ipset", "destroy", i.setV6)
	}
	_ = runWithConfig(ctx, i.cfg, "ipset", "flush", i.set)
	return ignoreMissingFirewallObject(runWithConfig(ctx, i.cfg, "ipset", "destroy", i.set))
}

func (i *IPSetIptables) initCommand(ctx context.Context, cmd, set, port, udpPort string) error {
	_ = runIptables(ctx, i.cfg, cmd, "-N", i.chain)
	_ = runIptables(ctx, i.cfg, cmd, "-F", i.chain)
	if err := runIptables(ctx, i.cfg, cmd, "-C", "INPUT", "-p", "tcp", "--dport", port, "-j", i.chain); err != nil {
		if err := runIptables(ctx, i.cfg, cmd, "-I", "INPUT", "1", "-p", "tcp", "--dport", port, "-j", i.chain); err != nil {
			return err
		}
	}
	if i.cfg.DropUDPKnockPort {
		udpArgs := []string{"-p", "udp", "--dport", udpPort, "-m", "comment", "--comment", "knockgate udp-passive", "-j", "DROP"}
		if err := runIptables(ctx, i.cfg, cmd, append([]string{"-C", "INPUT"}, udpArgs...)...); err != nil {
			if err := runIptables(ctx, i.cfg, cmd, append([]string{"-I", "INPUT", "1"}, udpArgs...)...); err != nil {
				return err
			}
		}
	}
	if err := runIptables(ctx, i.cfg, cmd, "-A", i.chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := runIptables(ctx, i.cfg, cmd, "-A", i.chain, "-m", "set", "--match-set", set, "src", "-j", "ACCEPT"); err != nil {
		return err
	}
	return runIptables(ctx, i.cfg, cmd, "-A", i.chain, "-p", "tcp", "--dport", port, "-j", "DROP")
}

func (i *IPSetIptables) cleanupCommand(ctx context.Context, cmd, port, udpPort string) {
	if i.cfg.DropUDPKnockPort {
		udpArgs := []string{"-p", "udp", "--dport", udpPort, "-m", "comment", "--comment", "knockgate udp-passive", "-j", "DROP"}
		for range maxCleanupDeletes {
			if err := runIptables(ctx, i.cfg, cmd, append([]string{"-D", "INPUT"}, udpArgs...)...); err != nil {
				break
			}
		}
	}
	for range maxCleanupDeletes {
		if err := runIptables(ctx, i.cfg, cmd, "-D", "INPUT", "-p", "tcp", "--dport", port, "-j", i.chain); err != nil {
			break
		}
	}
	_ = runIptables(ctx, i.cfg, cmd, "-F", i.chain)
	_ = runIptables(ctx, i.cfg, cmd, "-X", i.chain)
}
