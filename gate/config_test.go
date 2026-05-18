package gate

import (
	"errors"
	"strings"
	"testing"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/firewall"
	"github.com/libknock/libknock/knock"
)

func TestValidateGateConfigModeMatrix(t *testing.T) {
	secret := testSecret()
	validAuth := auth.ServerConfig{Secrets: auth.StaticSecrets{"client": secret}}
	validKnock := []knock.ClientSecret{{ClientID: "client", Secret: secret}}
	validFirewall := &recordingFirewall{}
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"zero defaults to auth-only", Config{Auth: validAuth}},
		{"auth-only", Config{Mode: AuthOnly, Auth: validAuth}},
		{"knock-auth-only", Config{Mode: KnockAuthOnly, Auth: validAuth, KnockMethod: knock.UDPMethod, KnockClients: validKnock}},
		{"knock-firewall-auth", Config{Mode: KnockFirewallAuth, Auth: validAuth, Firewall: validFirewall, KnockMethod: knock.UDPMethod, KnockClients: validKnock}},
		{"knock-firewall-only", Config{Mode: KnockFirewallOnly, Firewall: validFirewall, KnockMethod: knock.UDPMethod, KnockClients: validKnock}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := validateGateConfig(tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Mode == "" {
				t.Fatal("mode was not normalized")
			}
		})
	}
}

func TestValidateGateConfigFailures(t *testing.T) {
	secret := testSecret()
	validAuth := auth.ServerConfig{Secrets: auth.StaticSecrets{"client": secret}}
	validKnock := []knock.ClientSecret{{ClientID: "client", Secret: secret}}
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{"unsupported mode", Config{Mode: Mode("bogus")}, `unsupported gate mode "bogus"`},
		{"auth-only missing secrets", Config{Mode: AuthOnly}, auth.ErrMissingSecretResolver.Error()},
		{"knock-auth-only missing clients", Config{Mode: KnockAuthOnly, Auth: validAuth, KnockMethod: knock.UDPMethod}, auth.ErrMissingSecretResolver.Error()},
		{"knock-auth-only missing method", Config{Mode: KnockAuthOnly, Auth: validAuth, KnockClients: validKnock}, "gate knock method is required"},
		{"knock-firewall-auth noop firewall", Config{Mode: KnockFirewallAuth, Auth: validAuth, Firewall: firewall.Noop{}, KnockMethod: knock.UDPMethod, KnockClients: validKnock}, "gate knock-firewall-auth requires a non-noop firewall backend"},
		{"knock-firewall-only nil firewall", Config{Mode: KnockFirewallOnly, KnockMethod: knock.UDPMethod, KnockClients: validKnock}, "gate knock-firewall-only requires a non-noop firewall backend"},
		{"gate rejects passive method", Config{Mode: KnockAuthOnly, Auth: validAuth, KnockMethod: knock.UDPPassiveMethod, KnockClients: validKnock}, `gate knock method "udp-passive" does not support synchronous listener readiness`},
		{"gate rejects tcp syn method", Config{Mode: KnockAuthOnly, Auth: validAuth, KnockMethod: knock.TCPSYNMethod, KnockClients: validKnock}, `gate knock method "tcp-syn" does not support synchronous listener readiness`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateGateConfig(tc.cfg)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) && !errors.Is(err, auth.ErrMissingSecretResolver) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
