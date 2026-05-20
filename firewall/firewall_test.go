package firewall

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestNoopBackend(t *testing.T) {
	fw, err := New(Config{Backend: "noop"})
	if err != nil {
		t.Fatal(err)
	}
	if fw.Name() != "noop" {
		t.Fatalf("name = %q", fw.Name())
	}
	addr := netip.MustParseAddr("127.0.0.1")
	if err := fw.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fw.Allow(context.Background(), addr, 443, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := fw.Revoke(context.Background(), addr, 443); err != nil {
		t.Fatal(err)
	}
	if err := fw.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDescribeBackends(t *testing.T) {
	if !Describe("nftables").Timeout || !Describe("nftables").DropUDP {
		t.Fatal("nftables capabilities")
	}
	if Describe("iptables").Timeout || !Describe("iptables").DropUDP {
		t.Fatal("iptables capabilities")
	}
	if Describe("script").Timeout || Describe("script").DropUDP {
		t.Fatal("script capabilities")
	}
}

func TestScriptRequiresCommands(t *testing.T) {
	_, err := New(Config{Backend: "script"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRealBackendsRequireProtectedPort(t *testing.T) {
	for _, backend := range []string{"nftables", "iptables", "ipset-iptables", "script"} {
		t.Run(backend, func(t *testing.T) {
			cfg := Config{Backend: backend, Script: ScriptConfig{AllowCmd: "true", RevokeCmd: "true", CleanupCmd: "true"}}
			if _, err := New(cfg); err == nil {
				t.Fatal("expected missing protected port error")
			}
		})
	}
}

func TestNftablesRejectsUnsafeIdentifiers(t *testing.T) {
	cases := []NftablesConfig{
		{Family: "inet; delete table inet x"},
		{Table: "knock; flush ruleset"},
		{Chain: "bad-name"},
		{SetV4: "bad name"},
		{SetV6: "1bad"},
	}
	for _, cfg := range cases {
		if err := validateNftablesConfig(cfg); err == nil {
			t.Fatalf("expected invalid nftables config for %+v", cfg)
		}
	}
	if err := validateNftablesConfig(NftablesConfig{Family: "inet", Table: "knock_gateway", Chain: "input", SetV4: "allowed_clients_v4", SetV6: "allowed_clients_v6"}); err != nil {
		t.Fatal(err)
	}
}

func TestWithPortInjectsConfigurableBackendPort(t *testing.T) {
	fw := NewScript(Config{Backend: "script", Script: ScriptConfig{AllowCmd: "true", RevokeCmd: "true", CleanupCmd: "true"}})
	configured, err := WithPort(fw, 9443)
	if err != nil {
		t.Fatal(err)
	}
	script, ok := configured.(*Script)
	if !ok {
		t.Fatalf("configured backend type = %T", configured)
	}
	if script.cfg.Port != 9443 {
		t.Fatalf("port = %d, want 9443", script.cfg.Port)
	}
}

func TestWithPortRejectsNilBackend(t *testing.T) {
	if _, err := WithPort(nil, 443); err == nil {
		t.Fatal("WithPort accepted nil backend")
	}
}

func TestWithPortPreservesNoopPointer(t *testing.T) {
	noop := &Noop{}
	configured, err := WithPort(noop, 0)
	if err != nil {
		t.Fatal(err)
	}
	if configured != noop {
		t.Fatalf("configured backend = %T, want original noop pointer", configured)
	}
}

func TestBackendsRejectUnboundPortBeforeCommand(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.10")
	for _, tc := range []struct {
		name string
		fw   Backend
	}{
		{name: "nftables", fw: NewNftables(Config{Port: 443}, "nftables")},
		{name: "ipset-iptables", fw: NewIPSetIptables(Config{Port: 443})},
		{name: "iptables", fw: NewIptables(Config{Port: 443})},
		{name: "script", fw: NewScript(Config{Port: 443, Script: ScriptConfig{AllowCmd: "true", RevokeCmd: "true", CleanupCmd: "true"}})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fw.Allow(context.Background(), addr, 444, time.Second); err == nil || !strings.Contains(err.Error(), "bound to protected port 443") {
				t.Fatalf("Allow err = %v, want bound port error", err)
			}
			if checker, ok := tc.fw.(Checker); ok {
				if _, err := checker.IsAllowed(context.Background(), addr, 444); err == nil {
					t.Fatal("IsAllowed succeeded for unbound port")
				}
			}
			if err := tc.fw.Revoke(context.Background(), addr, 444); err == nil {
				t.Fatal("Revoke succeeded for unbound port")
			}
		})
	}
}

func TestIgnoreMissingFirewallObject(t *testing.T) {
	for _, msg := range []string{
		"nft -f - failed: exit status 1: No such file or directory",
		"delete table inet knock_gateway failed: No such table",
		"ipset destroy failed: The set with the given name does not exist",
		"entry not in set",
	} {
		if err := ignoreMissingFirewallObject(errors.New(msg)); err != nil {
			t.Fatalf("missing object error was not ignored: %v", err)
		}
	}
	if err := ignoreMissingFirewallObject(errors.New("permission denied")); err == nil {
		t.Fatal("non-missing firewall error was ignored")
	}
}

type captureRunner struct {
	failVersion map[string]bool
	commands    []string
	inputs      []string
}

func (r *captureRunner) Run(_ context.Context, name string, args ...string) error {
	r.commands = append(r.commands, strings.Join(append([]string{name}, args...), " "))
	if len(args) == 1 && args[0] == "--version" && r.failVersion[name] {
		return errors.New("missing command")
	}
	return nil
}

func (r *captureRunner) RunInput(_ context.Context, input, name string, args ...string) error {
	r.commands = append(r.commands, strings.Join(append([]string{name}, args...), " "))
	r.inputs = append(r.inputs, input)
	return nil
}

func TestBackendsUseConfiguredRunner(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.10")
	for _, tc := range []struct {
		name string
		run  func(*captureRunner) error
	}{
		{name: "nftables", run: func(r *captureRunner) error {
			fw := NewNftables(Config{Port: 443, AllowSeconds: 10, Runner: r}, "nftables")
			if err := fw.Allow(context.Background(), addr, 443, time.Second); err != nil {
				return err
			}
			if _, err := fw.IsAllowed(context.Background(), addr, 443); err != nil {
				return err
			}
			if err := fw.Revoke(context.Background(), addr, 443); err != nil {
				return err
			}
			return fw.Cleanup(context.Background())
		}},
		{name: "iptables", run: func(r *captureRunner) error {
			r.failVersion = map[string]bool{"ip6tables": true}
			fw := NewIptables(Config{Port: 443, Runner: r})
			if err := fw.Allow(context.Background(), addr, 443, time.Second); err != nil {
				return err
			}
			if _, err := fw.IsAllowed(context.Background(), addr, 443); err != nil {
				return err
			}
			if err := fw.Revoke(context.Background(), addr, 443); err != nil {
				return err
			}
			return nil
		}},
		{name: "ipset-iptables", run: func(r *captureRunner) error {
			r.failVersion = map[string]bool{"ip6tables": true}
			fw := NewIPSetIptables(Config{Port: 443, AllowSeconds: 10, Runner: r})
			if err := fw.Allow(context.Background(), addr, 443, time.Second); err != nil {
				return err
			}
			if err := fw.Revoke(context.Background(), addr, 443); err != nil {
				return err
			}
			return nil
		}},
		{name: "script", run: func(r *captureRunner) error {
			fw := NewScript(Config{Port: 443, Runner: r, Script: ScriptConfig{AllowCmd: "allow", RevokeCmd: "revoke", CleanupCmd: "cleanup"}})
			if err := fw.Allow(context.Background(), addr, 443, time.Second); err != nil {
				return err
			}
			if err := fw.Revoke(context.Background(), addr, 443); err != nil {
				return err
			}
			return fw.Cleanup(context.Background())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &captureRunner{}
			if err := tc.run(r); err != nil {
				t.Fatal(err)
			}
			if len(r.commands) == 0 {
				t.Fatal("runner did not capture commands")
			}
		})
	}
}

func TestIPSetIptablesWithConfigInjectsPort(t *testing.T) {
	fw := NewIPSetIptables(Config{})
	configured, err := fw.WithConfig(Config{Port: 8443, AllowSeconds: 10})
	if err != nil {
		t.Fatal(err)
	}
	ipset, ok := configured.(*IPSetIptables)
	if !ok {
		t.Fatalf("configured backend type = %T", configured)
	}
	if ipset.cfg.Port != 8443 {
		t.Fatalf("port = %d, want 8443", ipset.cfg.Port)
	}
}

func TestNftablesRejectsZeroAllowSeconds(t *testing.T) {
	fw := NewNftables(Config{Port: 443, Runner: &captureRunner{}}, "nftables")
	if err := fw.Init(context.Background()); err == nil {
		t.Fatal("Init succeeded with zero AllowSeconds")
	}
}

type helpVersionRunner struct{ commands []string }

func (r *helpVersionRunner) Run(_ context.Context, name string, args ...string) error {
	r.commands = append(r.commands, strings.Join(append([]string{name}, args...), " "))
	if len(args) == 1 && args[0] == "--help" {
		return nil
	}
	return errors.New("unexpected probe args")
}
func (r *helpVersionRunner) RunInput(context.Context, string, string, ...string) error { return nil }

func TestFirewallCommandExistsUsesHelpRunnerProbe(t *testing.T) {
	r := &helpVersionRunner{}
	if !firewallCommandExists(Config{Runner: r}, "ip6tables") {
		t.Fatal("command should exist with --help runner probe")
	}
	if got := r.commands; len(got) != 1 || got[0] != "ip6tables --help" {
		t.Fatalf("commands = %v", got)
	}
}

func TestIptablesRevokeIgnoresMissingRule(t *testing.T) {
	r := &missingRuleRunner{}
	fw := NewIptables(Config{Port: 443, Runner: r})
	if err := fw.Revoke(context.Background(), netip.MustParseAddr("192.0.2.10"), 443); err != nil {
		t.Fatalf("Revoke missing rule err = %v", err)
	}
}

type missingRuleRunner struct{}

func (missingRuleRunner) Run(_ context.Context, name string, args ...string) error {
	if len(args) > 0 && args[0] == "--help" {
		return nil
	}
	return errors.New("Bad rule (does a matching rule exist in that chain?)")
}
func (missingRuleRunner) RunInput(context.Context, string, string, ...string) error { return nil }

func TestBackendsRoundSubsecondTTLUpToOneSecond(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.10")
	for _, tc := range []struct {
		name string
		run  func(*captureRunner) error
		want string
	}{
		{name: "nftables", run: func(r *captureRunner) error {
			return NewNftables(Config{Port: 443, Runner: r}, "nftables").Allow(context.Background(), addr, 443, 500*time.Millisecond)
		}, want: "timeout 1s"},
		{name: "ipset-iptables", run: func(r *captureRunner) error {
			return NewIPSetIptables(Config{Port: 443, Runner: r}).Allow(context.Background(), addr, 443, 500*time.Millisecond)
		}, want: "timeout 1"},
		{name: "script", run: func(r *captureRunner) error {
			return NewScript(Config{Port: 443, Runner: r, Script: ScriptConfig{AllowCmd: "allow", RevokeCmd: "revoke", CleanupCmd: "cleanup"}}).Allow(context.Background(), addr, 443, 500*time.Millisecond)
		}, want: " 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &captureRunner{}
			if err := tc.run(r); err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(append(r.commands, r.inputs...), "\n")
			if !strings.Contains(joined, tc.want) {
				t.Fatalf("commands/inputs = %q, want %q", joined, tc.want)
			}
		})
	}
}

func TestScriptValidateChecksCommandsWithoutSideEffects(t *testing.T) {
	fw := NewScript(Config{Port: 443, Script: ScriptConfig{AllowCmd: "definitely-missing-libknock-allow", RevokeCmd: "true", CleanupCmd: "true"}})
	if err := fw.Validate(); err == nil {
		t.Fatal("Validate accepted missing command with nil runner")
	}
	r := &captureRunner{}
	fw = NewScript(Config{Port: 443, Runner: r, Script: ScriptConfig{AllowCmd: "allow", RevokeCmd: "revoke", CleanupCmd: "cleanup"}})
	if err := fw.Validate(); err != nil {
		t.Fatalf("Validate with custom runner: %v", err)
	}
	if len(r.commands) != 0 {
		t.Fatalf("Validate executed commands: %v", r.commands)
	}
}
