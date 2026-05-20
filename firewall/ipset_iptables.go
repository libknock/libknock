package firewall

import (
	"context"
	"errors"
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
	cfg = cfg.WithDefaults()
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
	if err := ignoreMissingFirewallObject(runWithConfig(ctx, i.cfg, "ipset", "flush", i.set)); err != nil {
		return errors.Join(err, i.cleanupDetached())
	}
	if err := i.cleanupCommand(ctx, "iptables", port, udpPort); err != nil {
		return errors.Join(err, i.cleanupDetached())
	}
	if err := i.initCommand(ctx, "iptables", i.set, port, udpPort); err != nil {
		return errors.Join(err, i.cleanupDetached())
	}
	if ipv6Enabled(i.cfg, i.Name()) {
		if err := runWithConfig(ctx, i.cfg, "ipset", "create", i.setV6, "hash:ip", "family", "inet6", "timeout", strconv.Itoa(i.cfg.AllowSeconds), "-exist"); err != nil {
			return errors.Join(err, i.cleanupDetached())
		}
		if err := ignoreMissingFirewallObject(runWithConfig(ctx, i.cfg, "ipset", "flush", i.setV6)); err != nil {
			return errors.Join(err, i.cleanupDetached())
		}
		if err := i.cleanupCommand(ctx, "ip6tables", port, udpPort); err != nil {
			return errors.Join(err, i.cleanupDetached())
		}
		if err := i.initCommand(ctx, "ip6tables", i.setV6, port, udpPort); err != nil {
			return errors.Join(err, i.cleanupDetached())
		}
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
		if !ipv6Enabled(i.cfg, i.Name()) {
			return errIPv6Unsupported("ipset-iptables")
		}
		set = i.setV6
	}
	return runWithConfig(ctx, i.cfg, "ipset", "add", set, addr.String(), "timeout", strconv.Itoa(seconds), "-exist")
}

func (i *IPSetIptables) IsAllowed(ctx context.Context, addr netip.Addr, port int) (bool, error) {
	if err := validateBoundFirewallPort(i.Name(), i.cfg.Port, port); err != nil {
		return false, err
	}
	set := i.set
	if toIP(addr).To4() == nil {
		if !ipv6Enabled(i.cfg, i.Name()) {
			return false, nil
		}
		set = i.setV6
	}
	if err := runWithConfig(ctx, i.cfg, "ipset", "test", set, addr.String()); err != nil {
		if isMissingFirewallObject(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (i *IPSetIptables) Revoke(ctx context.Context, addr netip.Addr, port int) error {
	if err := validateBoundFirewallPort(i.Name(), i.cfg.Port, port); err != nil {
		return err
	}
	set := i.set
	if toIP(addr).To4() == nil {
		if !ipv6Enabled(i.cfg, i.Name()) {
			return nil
		}
		set = i.setV6
	}
	return ignoreMissingFirewallObject(runWithConfig(ctx, i.cfg, "ipset", "del", set, addr.String()))
}

func (i *IPSetIptables) Cleanup(ctx context.Context) error {
	port := strconv.Itoa(i.cfg.Port)
	udpPort := strconv.Itoa(udpKnockPort(i.cfg))
	err := i.cleanupCommand(ctx, "iptables", port, udpPort)
	if ipv6Enabled(i.cfg, i.Name()) {
		err = errors.Join(err, i.cleanupCommand(ctx, "ip6tables", port, udpPort))
		err = errors.Join(err, ignoreMissingFirewallObject(runWithConfig(ctx, i.cfg, "ipset", "flush", i.setV6)))
		err = errors.Join(err, ignoreMissingFirewallObject(runWithConfig(ctx, i.cfg, "ipset", "destroy", i.setV6)))
	}
	err = errors.Join(err, ignoreMissingFirewallObject(runWithConfig(ctx, i.cfg, "ipset", "flush", i.set)))
	err = errors.Join(err, ignoreMissingFirewallObject(runWithConfig(ctx, i.cfg, "ipset", "destroy", i.set)))
	return err
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

func (i *IPSetIptables) cleanupCommand(ctx context.Context, cmd, port, udpPort string) error {
	var err error
	if i.cfg.DropUDPKnockPort {
		udpArgs := []string{"-p", "udp", "--dport", udpPort, "-m", "comment", "--comment", "knockgate udp-passive", "-j", "DROP"}
		for range maxCleanupDeletes {
			if deleteErr := runIptables(ctx, i.cfg, cmd, append([]string{"-D", "INPUT"}, udpArgs...)...); deleteErr != nil {
				if !isMissingFirewallObject(deleteErr) {
					err = errors.Join(err, deleteErr)
				}
				break
			}
		}
	}
	for range maxCleanupDeletes {
		if deleteErr := runIptables(ctx, i.cfg, cmd, "-D", "INPUT", "-p", "tcp", "--dport", port, "-j", i.chain); deleteErr != nil {
			if !isMissingFirewallObject(deleteErr) {
				err = errors.Join(err, deleteErr)
			}
			break
		}
	}
	err = errors.Join(err, ignoreMissingFirewallObject(runIptables(ctx, i.cfg, cmd, "-F", i.chain)))
	err = errors.Join(err, ignoreMissingFirewallObject(runIptables(ctx, i.cfg, cmd, "-X", i.chain)))
	return err
}

func (i *IPSetIptables) cleanupDetached() error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), defaultCommandTimeout)
	defer cancel()
	return i.Cleanup(cleanupCtx)
}
