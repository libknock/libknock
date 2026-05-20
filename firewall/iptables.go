package firewall

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"time"
)

type Iptables struct {
	cfg   Config
	chain string
}

func NewIptables(cfg Config) *Iptables {
	cfg = cfg.WithDefaults()
	chain := cfg.Iptables.Chain
	if chain == "" {
		chain = "KNOCK_GATEWAY"
	}
	return &Iptables{cfg: cfg, chain: chain}
}

func (i *Iptables) Name() string { return "iptables" }

func (i *Iptables) Config() Config { return i.cfg }
func (i *Iptables) WithConfig(cfg Config) (Backend, error) {
	if err := validateFirewallPort(cfg.Port, i.Name()); err != nil {
		return nil, err
	}
	return NewIptables(cfg), nil
}

func (i *Iptables) Init(ctx context.Context) error {
	port := strconv.Itoa(i.cfg.Port)
	udpPort := strconv.Itoa(udpKnockPort(i.cfg))
	if err := i.cleanupCommand(ctx, "iptables", port, udpPort); err != nil {
		return err
	}
	if err := i.initCommand(ctx, "iptables", port, udpPort); err != nil {
		cleanupErr := i.cleanupDetached()
		return errors.Join(err, cleanupErr)
	}
	if ipv6Enabled(i.cfg, i.Name()) {
		if err := i.cleanupCommand(ctx, "ip6tables", port, udpPort); err != nil {
			cleanupErr := i.cleanupDetached()
			return errors.Join(err, cleanupErr)
		}
		if err := i.initCommand(ctx, "ip6tables", port, udpPort); err != nil {
			cleanupErr := i.cleanupDetached()
			return errors.Join(err, cleanupErr)
		}
	}
	return nil
}

func (i *Iptables) Allow(ctx context.Context, addr netip.Addr, port int, ttl time.Duration) error {
	// Plain iptables rules have no native per-rule timeout; gate/relay own ttl
	// enforcement by scheduling a later Revoke and Init/Cleanup removes managed
	// rules left by unclean exits.
	_ = ttl
	if err := validateBoundFirewallPort(i.Name(), i.cfg.Port, port); err != nil {
		return err
	}
	cmd := "iptables"
	if toIP(addr).To4() == nil {
		if !ipv6Enabled(i.cfg, i.Name()) {
			return errIPv6Unsupported("iptables")
		}
		cmd = "ip6tables"
	}
	args := []string{"-s", addr.String(), "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"}
	if err := runIptables(ctx, i.cfg, cmd, append([]string{"-C", i.chain}, args...)...); err == nil {
		return nil
	}
	return runIptables(ctx, i.cfg, cmd, append([]string{"-I", i.chain, "1"}, args...)...)
}

func (i *Iptables) IsAllowed(ctx context.Context, addr netip.Addr, port int) (bool, error) {
	if err := validateBoundFirewallPort(i.Name(), i.cfg.Port, port); err != nil {
		return false, err
	}
	cmd := "iptables"
	if toIP(addr).To4() == nil {
		if !ipv6Enabled(i.cfg, i.Name()) {
			return false, nil
		}
		cmd = "ip6tables"
	}
	args := []string{"-s", addr.String(), "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"}
	if err := runIptables(ctx, i.cfg, cmd, append([]string{"-C", i.chain}, args...)...); err != nil {
		if isMissingFirewallObject(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (i *Iptables) Revoke(ctx context.Context, addr netip.Addr, port int) error {
	if err := validateBoundFirewallPort(i.Name(), i.cfg.Port, port); err != nil {
		return err
	}
	cmd := "iptables"
	if toIP(addr).To4() == nil {
		if !ipv6Enabled(i.cfg, i.Name()) {
			return nil
		}
		cmd = "ip6tables"
	}
	return ignoreMissingFirewallObject(runIptables(ctx, i.cfg, cmd, "-D", i.chain, "-s", addr.String(), "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"))
}

func (i *Iptables) Cleanup(ctx context.Context) error {
	port := strconv.Itoa(i.cfg.Port)
	udpPort := strconv.Itoa(udpKnockPort(i.cfg))
	err := i.cleanupCommand(ctx, "iptables", port, udpPort)
	if ipv6Enabled(i.cfg, i.Name()) {
		err = errors.Join(err, i.cleanupCommand(ctx, "ip6tables", port, udpPort))
	}
	return err
}

func (i *Iptables) initCommand(ctx context.Context, cmd, port, udpPort string) error {
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
	return runIptables(ctx, i.cfg, cmd, "-A", i.chain, "-p", "tcp", "--dport", port, "-j", "DROP")
}

const maxCleanupDeletes = 1000

func (i *Iptables) cleanupCommand(ctx context.Context, cmd, port, udpPort string) error {
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

func (i *Iptables) cleanupDetached() error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), defaultCommandTimeout)
	defer cancel()
	return i.Cleanup(cleanupCtx)
}
