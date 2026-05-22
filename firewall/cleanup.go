package firewall

import (
	"context"
	"errors"
)

const maxCleanupDeletes = 1000

type iptablesCleanupConfig struct {
	FirewallConfig Config
	Chain          string
	Command        string
	TCPPort        string
	UDPPort        string
}

func cleanupIptablesRules(ctx context.Context, cfg iptablesCleanupConfig) error {
	var err error
	if cfg.FirewallConfig.DropUDPKnockPort {
		udpArgs := []string{"-p", "udp", "--dport", cfg.UDPPort, "-m", "comment", "--comment", "knockgate udp-passive", "-j", "DROP"}
		for range maxCleanupDeletes {
			if deleteErr := runIptables(ctx, cfg.FirewallConfig, cfg.Command, append([]string{"-D", "INPUT"}, udpArgs...)...); deleteErr != nil {
				if !isMissingFirewallObject(deleteErr) {
					err = errors.Join(err, deleteErr)
				}
				break
			}
		}
	}
	for range maxCleanupDeletes {
		if deleteErr := runIptables(ctx, cfg.FirewallConfig, cfg.Command, "-D", "INPUT", "-p", "tcp", "--dport", cfg.TCPPort, "-j", cfg.Chain); deleteErr != nil {
			if !isMissingFirewallObject(deleteErr) {
				err = errors.Join(err, deleteErr)
			}
			break
		}
	}
	err = errors.Join(err, ignoreMissingFirewallObject(runIptables(ctx, cfg.FirewallConfig, cfg.Command, "-F", cfg.Chain)))
	err = errors.Join(err, ignoreMissingFirewallObject(runIptables(ctx, cfg.FirewallConfig, cfg.Command, "-X", cfg.Chain)))
	return err
}

func cleanupBackendDetached(cleanup func(context.Context) error) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), defaultCommandTimeout)
	defer cancel()
	return cleanup(cleanupCtx)
}
