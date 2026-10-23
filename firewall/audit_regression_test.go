package firewall

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestIptablesRejectsBuiltInChains(t *testing.T) {
	for _, chain := range []string{"INPUT", "input", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING", "ACCEPT", "DROP"} {
		if err := validateIptablesConfig(IptablesConfig{Chain: chain}); err == nil {
			t.Fatalf("chain %q accepted", chain)
		}
	}
	if err := validateIptablesConfig(IptablesConfig{Chain: "KNOCK_GATEWAY_SSH"}); err != nil {
		t.Fatalf("custom chain rejected: %v", err)
	}
}

func TestIptablesBackendsRefuseReservedChainBeforeRunningCommands(t *testing.T) {
	runner := &countingRunner{}
	cfg := Config{Port: 22, Runner: runner, Iptables: IptablesConfig{Chain: "INPUT"}}
	if err := NewIptables(cfg).Init(context.Background()); err == nil {
		t.Fatal("iptables Init accepted INPUT chain")
	}
	if err := NewIptables(cfg).Cleanup(context.Background()); err == nil {
		t.Fatal("iptables Cleanup accepted INPUT chain")
	}
	if err := NewIPSetIptables(cfg).Init(context.Background()); err == nil {
		t.Fatal("ipset-iptables Init accepted INPUT chain")
	}
	if err := NewIPSetIptables(cfg).Cleanup(context.Background()); err == nil {
		t.Fatal("ipset-iptables Cleanup accepted INPUT chain")
	}
	if runner.calls != 0 {
		t.Fatalf("ran %d firewall commands for a reserved chain", runner.calls)
	}
	if _, err := (&Iptables{}).WithConfig(cfg); err == nil {
		t.Fatal("iptables WithConfig accepted INPUT chain")
	}
}

type countingRunner struct{ calls int }

func (r *countingRunner) Run(context.Context, string, ...string) error {
	r.calls++
	return nil
}

func (r *countingRunner) RunInput(context.Context, string, string, ...string) error {
	r.calls++
	return nil
}

// Renewing an nftables lease must be a single atomic nft transaction so the
// element is never briefly absent from the allow set.
func TestNftablesAllowRenewIsSingleAtomicBatch(t *testing.T) {
	r := &firewallDryRunRunner{}
	fw := NewNftables(Config{Port: 9443, AllowSeconds: 60, Runner: r}, "nftables")
	before := len(r.inputs)
	if err := fw.Allow(context.Background(), netip.MustParseAddr("192.0.2.10"), 9443, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	inputs := r.inputs[before:]
	if len(inputs) != 1 {
		t.Fatalf("Allow issued %d nft batches, want 1: %q", len(inputs), inputs)
	}
	want := "add element inet knock_gateway allowed_clients_v4 { 192.0.2.10 timeout 2s }\n" +
		"delete element inet knock_gateway allowed_clients_v4 { 192.0.2.10 }\n" +
		"add element inet knock_gateway allowed_clients_v4 { 192.0.2.10 timeout 2s }\n"
	if inputs[0] != want {
		t.Fatalf("nft batch = %q, want %q", inputs[0], want)
	}
}
