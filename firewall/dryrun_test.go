package firewall

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestDryRunNftablesCommands(t *testing.T) {
	r := &firewallDryRunRunner{}
	fw := NewNftables(Config{Port: 9443, AllowSeconds: 60, Runner: r, DropUDPKnockPort: true, UDPKnockPort: 10000}, "nftables")
	if err := fw.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fw.Allow(context.Background(), netip.MustParseAddr("192.0.2.10"), 9443, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if ok, err := fw.IsAllowed(context.Background(), netip.MustParseAddr("192.0.2.10"), 9443); err != nil || !ok {
		t.Fatalf("IsAllowed = %v, %v", ok, err)
	}
	if err := fw.Revoke(context.Background(), netip.MustParseAddr("192.0.2.10"), 9443); err != nil {
		t.Fatal(err)
	}
	if err := fw.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(append(r.commands, r.inputs...), "\n")
	for _, want := range []string{"tcp dport 9443 drop", "udp dport 10000 drop", "add element inet knock_gateway allowed_clients_v4 { 192.0.2.10 timeout 2s }", "nft get element inet knock_gateway allowed_clients_v4 { 192.0.2.10 }", "delete table inet knock_gateway"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("dry-run nft commands missing %q\n%s", want, joined)
		}
	}
}

func TestNftablesExplicitIPv6DisableOmitsIPv6ObjectsAndRules(t *testing.T) {
	disabled := false
	r := &firewallDryRunRunner{}
	fw := NewNftables(Config{Port: 9443, Runner: r, EnableIPv6: &disabled}, "nftables")
	if err := fw.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.inputs, "\n")
	if strings.Contains(joined, "ipv6_addr") || strings.Contains(joined, "ip6 saddr") || strings.Contains(joined, "allowed_clients_v6") {
		t.Fatalf("IPv6 objects/rules present with IPv6 disabled:\n%s", joined)
	}
	if err := fw.Allow(context.Background(), netip.MustParseAddr("2001:db8::1"), 9443, time.Second); err == nil || !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("Allow IPv6 err = %v, want unsupported error", err)
	}
}

func TestNftablesDefaultsToIPv6WithoutIptables(t *testing.T) {
	r := &firewallDryRunRunner{failVersion: map[string]bool{"ip6tables": true}}
	fw := NewNftables(Config{Port: 9443, Runner: r}, "nftables")
	if err := fw.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.inputs, "\n")
	if !strings.Contains(joined, "type ipv6_addr") || !strings.Contains(joined, "ip6 saddr") {
		t.Fatalf("default nftables IPv6 objects/rules missing:\n%s", joined)
	}
}

func TestDryRunIptablesCommands(t *testing.T) {
	r := &firewallDryRunRunner{failVersion: map[string]bool{"ip6tables": true}}
	fw := NewIptables(Config{Port: 9443, Runner: r, DropUDPKnockPort: true, UDPKnockPort: 10000})
	if err := fw.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fw.Allow(context.Background(), netip.MustParseAddr("192.0.2.10"), 9443, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := fw.Revoke(context.Background(), netip.MustParseAddr("192.0.2.10"), 9443); err != nil {
		t.Fatal(err)
	}
	if err := fw.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.commands, "\n")
	for _, want := range []string{"iptables -w 5 -I INPUT 1 -p tcp --dport 9443 -j KNOCK_GATEWAY", "iptables -w 5 -I INPUT 1 -p udp --dport 10000 -m comment --comment knockgate udp-passive -j DROP", "iptables -w 5 -I KNOCK_GATEWAY 1 -s 192.0.2.10 -p tcp --dport 9443 -j ACCEPT", "iptables -w 5 -D KNOCK_GATEWAY -s 192.0.2.10 -p tcp --dport 9443 -j ACCEPT"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("dry-run iptables commands missing %q\n%s", want, joined)
		}
	}
}

func TestDryRunIPSetIptablesCommands(t *testing.T) {
	r := &firewallDryRunRunner{failVersion: map[string]bool{"ip6tables": true}}
	fw := NewIPSetIptables(Config{Port: 9443, AllowSeconds: 60, Runner: r, DropUDPKnockPort: true, UDPKnockPort: 10000})
	if err := fw.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fw.Allow(context.Background(), netip.MustParseAddr("192.0.2.10"), 9443, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := fw.Revoke(context.Background(), netip.MustParseAddr("192.0.2.10"), 9443); err != nil {
		t.Fatal(err)
	}
	if err := fw.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.commands, "\n")
	for _, want := range []string{"ipset create knock_gateway_allowed hash:ip timeout 60 -exist", "iptables -w 5 -A KNOCK_GATEWAY -m set --match-set knock_gateway_allowed src -j ACCEPT", "ipset add knock_gateway_allowed 192.0.2.10 timeout 2 -exist", "ipset del knock_gateway_allowed 192.0.2.10", "ipset destroy knock_gateway_allowed"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("dry-run ipset commands missing %q\n%s", want, joined)
		}
	}
}

func TestDryRunFirewallBoundPortValidationAndErrors(t *testing.T) {
	r := &firewallDryRunRunner{failContains: "-I KNOCK_GATEWAY 1 -s 192.0.2.10"}
	fw := NewIptables(Config{Port: 9443, Runner: r})
	if err := fw.Allow(context.Background(), netip.MustParseAddr("192.0.2.10"), 9444, time.Minute); err == nil || !strings.Contains(err.Error(), "bound to protected port 9443") {
		t.Fatalf("Allow wrong port err = %v", err)
	}
	if err := fw.Allow(context.Background(), netip.MustParseAddr("192.0.2.10"), 9443, time.Minute); err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("Allow injected err = %v", err)
	}
}

func TestDryRunCleanupIsIdempotent(t *testing.T) {
	r := &firewallDryRunRunner{failVersion: map[string]bool{"ip6tables": true}}
	fw := NewIptables(Config{Port: 9443, Runner: r, DropUDPKnockPort: true, UDPKnockPort: 10000})
	if err := fw.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fw.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.commands, "\n")
	if !strings.Contains(joined, "iptables -w 5 -F KNOCK_GATEWAY") || !strings.Contains(joined, "iptables -w 5 -X KNOCK_GATEWAY") {
		t.Fatalf("cleanup commands missing\n%s", joined)
	}
}

func TestDryRunDetectUsesConfiguredRunner(t *testing.T) {
	if got, err := Detect(Config{Runner: commandSetRunner{"nft": true}}); err != nil || got != "nftables" {
		t.Fatalf("Detect nft = %q, %v", got, err)
	}
	if got, err := Detect(Config{Runner: commandSetRunner{"ipset": true, "iptables": true}}); err != nil || got != "ipset-iptables" {
		t.Fatalf("Detect ipset = %q, %v", got, err)
	}
	if got, err := Detect(Config{Runner: commandSetRunner{"iptables": true}}); err != nil || got != "iptables" {
		t.Fatalf("Detect iptables = %q, %v", got, err)
	}
}

type commandSetRunner map[string]bool

func (r commandSetRunner) Run(_ context.Context, name string, args ...string) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "--version") && r[name] {
		return nil
	}
	return errors.New("command unavailable")
}
func (commandSetRunner) RunInput(context.Context, string, string, ...string) error { return nil }

type firewallDryRunRunner struct {
	failVersion  map[string]bool
	failContains string
	commands     []string
	inputs       []string
}

func (r *firewallDryRunRunner) Run(_ context.Context, name string, args ...string) error {
	cmd := strings.Join(append([]string{name}, args...), " ")
	r.commands = append(r.commands, cmd)
	if r.failContains != "" && strings.Contains(cmd, r.failContains) {
		return errors.New("injected failure")
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "--version") && r.failVersion[name] {
		return errors.New("missing command")
	}
	if op, i := iptablesOp(args); op != "" {
		switch op {
		case "-C":
			return errors.New("rule does not exist")
		case "-D":
			if len(args) > i+1 && args[i+1] == "INPUT" && countCommand(r.commands, name, args) >= 2 {
				return errors.New("rule does not exist")
			}
		}
	}
	return nil
}

func (r *firewallDryRunRunner) RunInput(_ context.Context, input, name string, args ...string) error {
	r.commands = append(r.commands, strings.Join(append([]string{name}, args...), " "))
	r.inputs = append(r.inputs, input)
	return nil
}

func countCommand(commands []string, name string, args []string) int {
	needle := strings.Join(append([]string{name}, args...), " ")
	count := 0
	for _, cmd := range commands {
		if cmd == needle {
			count++
		}
	}
	return count
}

func iptablesOp(args []string) (string, int) {
	for i, arg := range args {
		switch arg {
		case "-C", "-D":
			return arg, i
		}
	}
	return "", -1
}
