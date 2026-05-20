package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/libknock/libknock/knock"
)

const demoSecret = "base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

func TestServerRuntimeConvertsOldConfig(t *testing.T) {
	cfg := mustLoadConfig(t, `mode: server
server:
  tcp_listen: "127.0.0.1:10443"
  upstream: "127.0.0.1:22"
knock:
  method: udp-seq
  udp_knock_port: 10000
auth:
  clients:
    - client_id: client-a
      secret: `+demoSecret+`
firewall:
  backend: noop
limits:
  max_pending_auth: 9
  max_auth_workers: 3
`)
	rt, err := cfg.serverRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if rt.Listen != "127.0.0.1:10443" || rt.Upstream != "127.0.0.1:22" {
		t.Fatalf("bad endpoints: %#v", rt)
	}
	if rt.KnockMethod != knock.UDPSeqMethod || rt.KnockListen != "127.0.0.1:10000" || rt.KnockPort != 10000 {
		t.Fatalf("bad knock conversion: %#v", rt)
	}
	if got := string(rt.Secrets["client-a"]); got != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("secret = %q", got)
	}
	if rt.Firewall.Backend != "noop" || rt.Firewall.Port != 10443 {
		t.Fatalf("bad firewall: %#v", rt.Firewall)
	}
	if rt.MaxPendingAuth != 9 || rt.MaxAuthWorkers != 3 {
		t.Fatalf("bad limits: %d/%d", rt.MaxPendingAuth, rt.MaxAuthWorkers)
	}
}

func TestClientRuntimeConvertsOldConfig(t *testing.T) {
	cfg := mustLoadConfig(t, `mode: client
client:
  listen: "127.0.0.1:18080"
  server_addr: "198.51.100.10:10443"
  protected_tcp_port: 443
  client_id: client-a
  secret: `+demoSecret+`
knock:
  method: udp
  udp_knock_port: 10000
`)
	rt, err := cfg.clientRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if rt.Listen != "127.0.0.1:18080" || rt.ServerAddr != "198.51.100.10:10443" {
		t.Fatalf("bad endpoints: %#v", rt)
	}
	if rt.ServerPort != 443 || rt.UDPServerAddr != "198.51.100.10:10000" || rt.KnockMethod != knock.UDPMethod {
		t.Fatalf("bad client conversion: %#v", rt)
	}
}

func TestDryRunBuildsFirewallBackend(t *testing.T) {
	path := writeTempConfig(t, `mode: server
server:
  tcp_listen: "127.0.0.1:10443"
  upstream: "127.0.0.1:22"
auth:
  clients:
    - client_id: client-a
      secret: `+demoSecret+`
firewall:
  backend: script
`)
	if code := run([]string{"dry-run", "--config", path}); code == 0 {
		t.Fatal("dry-run unexpectedly succeeded without script firewall commands")
	}
}

func TestDryRunServerNoopSucceeds(t *testing.T) {
	path := writeTempConfig(t, `mode: server
server:
  tcp_listen: "127.0.0.1:10443"
  upstream: "127.0.0.1:22"
auth:
  clients:
    - client_id: client-a
      secret: `+demoSecret+`
firewall:
  backend: noop
`)
	if code := run([]string{"dry-run", "--config", path}); code != 0 {
		t.Fatalf("dry-run code = %d", code)
	}
}

func TestBuildServerUsesLibknockRelay(t *testing.T) {
	cfg := mustLoadConfig(t, `mode: server
server:
  tcp_listen: "127.0.0.1:10443"
  upstream: "127.0.0.1:22"
knock:
  method: udp
auth:
  clients:
    - client_id: client-a
      secret: `+demoSecret+`
firewall:
  backend: noop
`)
	g, summary, err := buildServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if g.Auth.Secrets == nil || g.Auth.ReplayCache == nil {
		t.Fatal("server auth was not built from libknock components")
	}
	if g.KnockMethod != knock.UDPMethod || summary.Firewall != "noop" || summary.Clients != 1 {
		t.Fatalf("bad gateway summary: %#v %#v", g, summary)
	}
}

func mustLoadConfig(t *testing.T, body string) fileConfig {
	t.Helper()
	cfg, err := loadConfig(writeTempConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServerRuntimeUsesAccessRemoveAfterFirstConnect(t *testing.T) {
	cfg := mustLoadConfig(t, `mode: server
server:
  tcp_listen: "127.0.0.1:10443"
  upstream: "127.0.0.1:22"
access:
  remove_after_first_connect: false
auth:
  clients:
    - client_id: client-a
      secret: `+demoSecret+`
firewall:
  backend: noop
  remove_after_auth: true
`)
	rt, err := cfg.serverRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if rt.RemoveAfterAuth {
		t.Fatal("access.remove_after_first_connect=false was ignored")
	}
}

func TestServerRuntimeRejectsUnsupportedOldFields(t *testing.T) {
	base := `mode: server
server:
  tcp_listen: "127.0.0.1:10443"
  upstream: "127.0.0.1:22"
auth:
  clients:
    - client_id: client-a
      secret: ` + demoSecret + `
firewall:
  backend: noop
`
	cases := map[string]string{
		"require_tcp_auth_false": base + `access:
  require_tcp_auth: false
`,
		"client_max_connections": `mode: server
server:
  tcp_listen: "127.0.0.1:10443"
  upstream: "127.0.0.1:22"
auth:
  clients:
    - client_id: client-a
      secret: ` + demoSecret + `
      max_connections: 2
firewall:
  backend: noop
`,
		"transport_method": base + `transport:
  method: aes-256-gcm
`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := mustLoadConfig(t, body)
			if _, err := cfg.serverRuntime(); err == nil {
				t.Fatal("expected unsupported field error")
			}
		})
	}
}

func TestLoadConfigRejectsLegacyJSONKnockOptions(t *testing.T) {
	for _, body := range []string{
		"knock_frame_format: json\n",
		"legacy_json: true\n",
		"allow_json_knock: true\n",
		"json_compat: true\n",
		"json_sequence_compat: true\n",
		"knock:\n  frame: json\n",
		"knock:\n  frame: legacy-json\n",
	} {
		t.Run(strings.ReplaceAll(strings.TrimSpace(body), "\n", "/"), func(t *testing.T) {
			_, err := loadConfig(writeTempConfig(t, "mode: server\n"+body))
			if err == nil || !strings.Contains(err.Error(), "binary-v1 is required") {
				t.Fatalf("loadConfig err = %v, want legacy rejection", err)
			}
		})
	}
}

func TestLoadConfigAllowsUnrelatedJSONKeys(t *testing.T) {
	_, err := loadConfig(writeTempConfig(t, `mode: server
log:
  format: json
output:
  json: true
`))
	if err != nil {
		t.Fatalf("loadConfig rejected unrelated json keys: %v", err)
	}
}

func TestKnockFrameConfigRequiresBinaryV1(t *testing.T) {
	_, err := loadConfig(writeTempConfig(t, `mode: server
server:
  tcp_listen: "127.0.0.1:10443"
  upstream: "127.0.0.1:22"
knock:
  frame: json
auth:
  clients:
    - client_id: client-a
      secret: `+demoSecret+`
firewall:
  backend: noop
`))
	if err == nil || !strings.Contains(err.Error(), "binary-v1") {
		t.Fatalf("loadConfig err = %v, want binary-v1 rejection", err)
	}
}

func TestDoctorServerNoopSucceeds(t *testing.T) {
	cfg := mustLoadConfig(t, `mode: server
server:
  tcp_listen: "127.0.0.1:10443"
  upstream: "127.0.0.1:22"
auth:
  clients:
    - client_id: client-a
      secret: `+demoSecret+`
firewall:
  backend: noop
`)
	checks, err := doctorServer(context.Background(), cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) == 0 {
		t.Fatal("expected doctor checks")
	}
}

func TestRunDoctorCmdReturnsNonZeroForBlockingFailure(t *testing.T) {
	oldStdout, oldStderr := os.Stdout, stderr
	out, err := os.CreateTemp(t.TempDir(), "doctor-stdout-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.Stdout, stderr = oldStdout, oldStderr
		_ = out.Close()
	}()
	os.Stdout = out
	stderr = out
	cfg := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(cfg, []byte(`mode: server
server:
  tcp_listen: "127.0.0.1:10443"
  upstream: "127.0.0.1:1"
auth:
  clients:
    - client_id: client-a
      secret: `+demoSecret+`
firewall:
  backend: noop
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runDoctorCmd([]string{"--config", cfg, "--check-upstream"}); code == 0 {
		t.Fatal("doctor returned zero for blocking failure")
	}
}

func TestServerRuntimeRejectsRemoveAfterAuthWithMultipleConnectionsPerKnock(t *testing.T) {
	cfg := mustLoadConfig(t, `mode: server
server:
  tcp_listen: "127.0.0.1:10443"
  upstream: "127.0.0.1:22"
auth:
  clients:
    - client_id: client-a
      secret: `+demoSecret+`
access:
  max_connections_per_knock: 2
firewall:
  backend: noop
  remove_after_auth: true
`)
	if _, err := cfg.serverRuntime(); err == nil || !strings.Contains(err.Error(), "remove_after_auth=true conflicts") {
		t.Fatalf("serverRuntime err = %v, want remove_after_auth conflict", err)
	}
}

func TestServerRuntimePassesFirewallEnableIPv6(t *testing.T) {
	cfg := mustLoadConfig(t, `mode: server
server:
  tcp_listen: "127.0.0.1:10443"
  upstream: "127.0.0.1:22"
auth:
  clients:
    - client_id: client-a
      secret: `+demoSecret+`
firewall:
  backend: noop
  enable_ipv6: false
`)
	rt, err := cfg.serverRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if rt.Firewall.EnableIPv6 == nil || *rt.Firewall.EnableIPv6 {
		t.Fatalf("EnableIPv6 = %#v, want false", rt.Firewall.EnableIPv6)
	}
}
