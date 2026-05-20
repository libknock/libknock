package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/libknock/libknock/firewall"
)

type doctorCheck struct {
	Name     string
	OK       bool
	Blocking bool
	Info     string
}

func runDoctorCmd(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", "", "server YAML config path")
	checkUpstream := fs.Bool("check-upstream", false, "attempt a TCP connection to server.upstream")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*config)
	if err != nil {
		return fail(err)
	}
	checks, err := doctorServer(signalContext(), cfg, *checkUpstream)
	printDoctorChecks(checks)
	return doctorExitCode(checks, err)
}

func doctorServer(ctx context.Context, cfg fileConfig, checkUpstream bool) ([]doctorCheck, error) {
	var checks []doctorCheck
	rt, err := cfg.serverRuntime()
	if err != nil {
		checks = append(checks, doctorCheck{Name: "config", OK: false, Blocking: true, Info: err.Error()})
		return checks, err
	}
	checks = append(checks, doctorCheck{Name: "config", OK: true, Info: "server config parsed"})
	g, summary, err := buildServer(cfg)
	if err != nil {
		checks = append(checks, doctorCheck{Name: "firewall build", OK: false, Blocking: true, Info: err.Error()})
		return checks, err
	}
	checks = append(checks, doctorCheck{Name: "runtime", OK: true, Info: fmt.Sprintf("listen=%s upstream=%s knock=%s firewall=%s", summary.Listen, summary.Upstream, summary.KnockMethod, summary.Firewall)})
	checks = append(checks, doctorCheck{Name: "firewall summary", OK: summary.Firewall != "noop", Blocking: false, Info: fmt.Sprintf("backend=%s installs_rules=%t port_hidden=%t allow_seconds=%d ipv6=%s", summary.Firewall, summary.FirewallInstalls, summary.PortHidden, summary.AllowSeconds, summary.IPv6)})
	probe, err := firewall.Probe(ctx, rt.Firewall)
	if err != nil {
		checks = append(checks, doctorCheck{Name: "firewall probe", OK: false, Blocking: true, Info: err.Error()})
		return checks, err
	}
	checks = append(checks, doctorCheck{Name: "firewall probe", OK: true, Info: fmt.Sprintf("backend=%s", probe.Backend)})
	checks = append(checks, doctorCheck{Name: "root", OK: probe.EUID == 0, Blocking: probe.Backend != "noop", Info: fmt.Sprintf("euid=%d", probe.EUID)})
	if probe.Backend != "noop" && probe.Backend != "script" {
		checks = append(checks, doctorCheck{Name: "CAP_NET_ADMIN", OK: probe.HasCAPNetAdmin, Blocking: true})
	}
	if summary.KnockMethod == "tcp-syn" || summary.KnockMethod == "tcp-syn-seq" {
		checks = append(checks, doctorCheck{Name: "CAP_NET_RAW", OK: probe.HasCAPNetRaw, Blocking: true})
	}
	for _, name := range []string{"nft", "iptables", "ipset"} {
		if path, ok := probe.Commands[name]; ok {
			checks = append(checks, doctorCheck{Name: name, OK: true, Info: path})
		}
	}
	if checkUpstream {
		d := net.Dialer{Timeout: nonzeroDuration(rt.UpstreamConnectTimeout, time.Second)}
		conn, err := d.DialContext(ctx, "tcp", rt.Upstream)
		if err != nil {
			checks = append(checks, doctorCheck{Name: "upstream", OK: false, Blocking: true, Info: err.Error()})
			return checks, err
		}
		_ = conn.Close()
		checks = append(checks, doctorCheck{Name: "upstream", OK: true, Info: rt.Upstream})
	}
	_ = g
	return checks, nil
}

func nonzeroDuration(v, fallback time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return fallback
}

func printDoctorChecks(checks []doctorCheck) {
	for _, check := range checks {
		status := "FAIL"
		if check.OK {
			status = "OK"
		}
		if check.Info != "" {
			_, _ = fmt.Fprintf(os.Stdout, "[%s] %s: %s\n", status, check.Name, check.Info)
		} else {
			_, _ = fmt.Fprintf(os.Stdout, "[%s] %s\n", status, check.Name)
		}
	}
}

func doctorExitCode(checks []doctorCheck, err error) int {
	blockingFailure := false
	for _, check := range checks {
		if !check.OK && check.Blocking {
			blockingFailure = true
		}
	}
	if blockingFailure {
		return 1
	}
	if err != nil {
		return fail(err)
	}
	return 0
}
