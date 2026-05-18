package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

const version = "libknock-compat"

var stderr io.Writer = os.Stderr

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "server":
		return runServerCmd(args[1:])
	case "client":
		return runClientCmd(args[1:])
	case "dry-run":
		return runDryRunCmd(args[1:])
	case "doctor":
		return runDoctorCmd(args[1:])
	case "version":
		_, _ = fmt.Fprintln(os.Stdout, version)
		return 0
	case "-h", "--help", "help":
		usage(os.Stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func runServerCmd(args []string) int {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", "", "server YAML config path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*config)
	if err != nil {
		return fail(err)
	}
	gateway, summary, err := buildServer(cfg)
	if err != nil {
		return fail(err)
	}
	printSummary(summary)
	return failCode(gateway.Run(signalContext()))
}

func runClientCmd(args []string) int {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", "", "client YAML config path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*config)
	if err != nil {
		return fail(err)
	}
	rt, dialer, summary, err := buildClient(cfg)
	if err != nil {
		return fail(err)
	}
	printSummary(summary)
	return failCode(runClient(signalContext(), rt, dialer))
}

func runDryRunCmd(args []string) int {
	fs := flag.NewFlagSet("dry-run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", "", "YAML config path")
	mode := fs.String("mode", "", "server or client; defaults to config mode")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*config)
	if err != nil {
		return fail(err)
	}
	m := *mode
	if m == "" {
		m = cfg.Mode
	}
	switch strings.ToLower(m) {
	case modeServer:
		_, summary, err := buildServer(cfg)
		if err != nil {
			return fail(err)
		}
		printSummary(summary)
	case modeClient:
		rt, err := cfg.clientRuntime()
		if err != nil {
			return fail(err)
		}
		printSummary(runSummary{Mode: modeClient, Listen: rt.Listen, ServerAddr: rt.ServerAddr, KnockMethod: rt.KnockMethod, Clients: 1})
	default:
		return fail(errors.New(`dry-run requires --mode server|client when config mode is empty`))
	}
	_, _ = fmt.Fprintln(os.Stdout, "dry-run: ok")
	return 0
}

func signalContext() context.Context {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() { <-ctx.Done(); stop() }()
	return ctx
}

func printSummary(s runSummary) {
	_, _ = fmt.Fprintf(os.Stdout, "mode=%s listen=%s", s.Mode, s.Listen)
	if s.Upstream != "" {
		_, _ = fmt.Fprintf(os.Stdout, " upstream=%s", s.Upstream)
	}
	if s.ServerAddr != "" {
		_, _ = fmt.Fprintf(os.Stdout, " server=%s", s.ServerAddr)
	}
	if s.KnockMethod != "" {
		_, _ = fmt.Fprintf(os.Stdout, " knock=%s", s.KnockMethod)
	}
	if s.Firewall != "" {
		_, _ = fmt.Fprintf(os.Stdout, " firewall=%s", s.Firewall)
	}
	if s.Clients > 0 {
		_, _ = fmt.Fprintf(os.Stdout, " clients=%d", s.Clients)
	}
	_, _ = fmt.Fprintln(os.Stdout)
}

func fail(err error) int { _, _ = fmt.Fprintln(stderr, "error:", err); return 1 }
func failCode(err error) int {
	if err == nil {
		return 0
	}
	return fail(err)
}
func usage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `usage: knock-proxy <command> [options]

commands:
  server  --config server.yaml
  client  --config client.yaml
  dry-run --config config.yaml [--mode server|client]
  doctor  --config server.yaml
  version`)
}
