package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/libknock/libknock/firewall"
)

const doctorSecret = "base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

func TestDoctorBlockingFailReturnsNonZero(t *testing.T) {
	path := writeTempConfig(t, `mode: server
server:
  tcp_listen: "127.0.0.1:10443"
  upstream: "127.0.0.1:22"
auth:
  clients:
    - client_id: client-a
      secret: `+doctorSecret+`
firewall:
  backend: made-up
`)
	if code := run([]string{"doctor", "--config", path}); code == 0 {
		t.Fatal("doctor succeeded for blocking firewall build failure")
	}
}

func TestDoctorWarnOnlyReturnsZero(t *testing.T) {
	checks := []doctorCheck{{Name: "root", OK: false, Blocking: false, Info: "euid=1000"}, {Name: "config", OK: true}}
	if got := doctorExitCode(checks, nil); got != 0 {
		t.Fatalf("warn-only doctor exit = %d", got)
	}
}

func TestDoctorBlockingChecks(t *testing.T) {
	for _, check := range []doctorCheck{{Name: "root", OK: false, Blocking: true}, {Name: "CAP_NET_ADMIN", OK: false, Blocking: true}, {Name: "CAP_NET_RAW", OK: false, Blocking: true}} {
		if got := doctorExitCode([]doctorCheck{check}, nil); got != 1 {
			t.Fatalf("%s exit = %d", check.Name, got)
		}
	}
}

func TestDoctorConfigParseFailureIsBlocking(t *testing.T) {
	checks, err := doctorServer(context.Background(), fileConfig{Mode: "client"}, false)
	if err == nil {
		t.Fatal("doctorServer unexpectedly accepted client config")
	}
	if len(checks) == 0 || checks[0].Name != "config" || checks[0].OK || !checks[0].Blocking {
		t.Fatalf("checks = %#v", checks)
	}
}

func TestDoctorFirewallBuildFailureIsBlocking(t *testing.T) {
	cfg := mustLoadConfig(t, `mode: server
server:
  tcp_listen: "127.0.0.1:10443"
  upstream: "127.0.0.1:22"
auth:
  clients:
    - client_id: client-a
      secret: `+doctorSecret+`
firewall:
  backend: script
  script:
    allow_cmd: allow
    revoke_cmd: revoke
    cleanup_cmd: cleanup
`)
	cfg.Firewall.Backend = "made-up"
	checks, err := doctorServer(context.Background(), cfg, false)
	if err == nil {
		t.Fatal("expected backend failure")
	}
	found := false
	for _, check := range checks {
		if check.Name == "firewall build" {
			found = true
			if check.OK || !check.Blocking {
				t.Fatalf("check = %#v", check)
			}
		}
	}
	if !found {
		t.Fatalf("no firewall build failure check: %#v", checks)
	}
}

func TestDoctorDryRunBoundaryDocumentationHelpers(t *testing.T) {
	if got := doctorExitCode([]doctorCheck{{Name: "dry-run", OK: true, Info: "config and backend constructed"}}, nil); got != 0 {
		t.Fatalf("dry-run style check exit = %d", got)
	}
	if got := doctorExitCode(nil, errors.New("unclassified")); got != 1 {
		t.Fatalf("unclassified err exit = %d", got)
	}
	if !strings.Contains(firewall.Noop{}.Name(), "noop") {
		t.Fatal("noop backend sanity check failed")
	}
}
