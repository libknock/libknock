package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/libknock/libknock"
	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/firewall"
	"github.com/libknock/libknock/knock"
	"github.com/libknock/libknock/relay"
)

type runSummary struct {
	Mode             string
	Listen           string
	Upstream         string
	ServerAddr       string
	KnockMethod      string
	Firewall         string
	FirewallInstalls bool
	PortHidden       bool
	AllowSeconds     int
	IPv6             string
	Clients          int
}

func buildServer(cfg fileConfig) (relay.Gateway, runSummary, error) {
	rt, err := cfg.serverRuntime()
	if err != nil {
		return relay.Gateway{}, runSummary{}, err
	}
	fw, err := firewall.New(rt.Firewall)
	if err != nil {
		return relay.Gateway{}, runSummary{}, fmt.Errorf("firewall: %w", err)
	}
	g := relay.Gateway{
		Listen:                 rt.Listen,
		Upstream:               rt.Upstream,
		Auth:                   auth.ServerConfig{ServerPort: rt.Port, Secrets: auth.NewStaticSecretResolver(rt.Secrets), ReplayCache: auth.NewMemoryReplayCache(rt.NonceCacheTTL), AuthTimeout: rt.AuthTimeout, TimeWindow: rt.AuthTimeWindow},
		Firewall:               fw,
		KnockMethod:            rt.KnockMethod,
		KnockListen:            rt.KnockListen,
		KnockPort:              rt.KnockPort,
		KnockClients:           rt.KnockClients,
		KnockTimeWindow:        rt.KnockTimeWindow,
		KnockMaxFrameSize:      rt.KnockMaxFrameSize,
		KnockSequence:          rt.Sequence,
		KnockNonceTTL:          rt.NonceTTL,
		AllowTTL:               rt.AllowTTL,
		UpstreamConnectTimeout: rt.UpstreamConnectTimeout,
		IdleTimeout:            rt.IdleTimeout,
		RemoveAfterAuth:        rt.RemoveAfterAuth,
		MaxConnectionsPerKnock: rt.MaxConnectionsPerKnock,
		DisableSessionBinding:  rt.DisableSessionBinding,
		MaxPendingAuth:         rt.MaxPendingAuth,
		MaxAuthWorkers:         rt.MaxAuthWorkers,
		Events:                 textEvents{},
	}
	return g, runSummary{Mode: modeServer, Listen: rt.Listen, Upstream: rt.Upstream, KnockMethod: rt.KnockMethod, Firewall: fw.Name(), FirewallInstalls: fw.Name() != "noop", PortHidden: fw.Name() != "noop", AllowSeconds: rt.Firewall.WithDefaults().AllowSeconds, IPv6: ipv6Summary(rt.Firewall), Clients: len(rt.Secrets)}, nil
}

func ipv6Summary(cfg firewall.Config) string {
	if cfg.EnableIPv6 == nil {
		return "auto"
	}
	if *cfg.EnableIPv6 {
		return "enabled"
	}
	return "disabled"
}

func buildClient(cfg fileConfig) (clientRuntime, libknock.Dialer, runSummary, error) {
	rt, err := cfg.clientRuntime()
	if err != nil {
		return clientRuntime{}, libknock.Dialer{}, runSummary{}, err
	}
	knockAddr := rt.ServerAddr
	if rt.KnockMethod == knock.UDPMethod || rt.KnockMethod == knock.UDPPassiveMethod || rt.KnockMethod == knock.UDPSeqMethod || rt.KnockMethod == knock.UDPPassiveSeq {
		knockAddr = rt.UDPServerAddr
	}
	dialer := libknock.Dialer{Base: &net.Dialer{Timeout: rt.ConnectTimeout}, Config: auth.ClientConfig{ClientID: rt.ClientID, Secret: rt.Secret, ServerPort: rt.ServerPort, AuthTimeout: rt.AuthTimeout, Knock: &knockSender{method: rt.KnockMethod, opts: knock.SendOptions{ServerAddr: knockAddr, ClientID: rt.ClientID, Secret: rt.Secret, ServerPort: rt.ServerPort, TimeWindow: rt.KnockTimeWindow, MaxFrameSize: rt.KnockMaxFrameSize, Sequence: rt.Sequence}, retry: rt.KnockRetry, timeout: rt.KnockTimeout}}}
	return rt, dialer, runSummary{Mode: modeClient, Listen: rt.Listen, ServerAddr: rt.ServerAddr, KnockMethod: rt.KnockMethod, Clients: 1}, nil
}

func runClient(ctx context.Context, rt clientRuntime, dialer libknock.Dialer) error {
	ln, err := net.Listen("tcp", rt.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go handleClientConn(ctx, conn, rt, dialer)
	}
}

func handleClientConn(ctx context.Context, local net.Conn, rt clientRuntime, dialer libknock.Dialer) {
	defer local.Close()
	remote, err := dialer.DialContext(ctx, "tcp", rt.ServerAddr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "client dial failed: %v\n", err)
		return
	}
	defer remote.Close()
	_ = relay.Bidirectional(local, remote, rt.IdleTimeout)
}

type knockSender struct {
	method  string
	opts    knock.SendOptions
	retry   int
	timeout time.Duration
}

func (s *knockSender) SetSessionID(sessionID []byte) {
	s.opts.SessionID = append([]byte(nil), sessionID...)
}

func (s *knockSender) Knock(ctx context.Context) error {
	attempts := s.retry + 1
	if attempts < 1 {
		attempts = 1
	}
	var last error
	for i := 0; i < attempts; i++ {
		callCtx := ctx
		cancel := func() {}
		if s.timeout > 0 {
			callCtx, cancel = context.WithTimeout(ctx, s.timeout)
		}
		last = knock.SendMethod(callCtx, s.method, s.opts)
		cancel()
		if last == nil {
			return nil
		}
	}
	return last
}

type textEvents struct{}

func (textEvents) OnKnockOK(ev relay.KnockEvent) {
	_, _ = fmt.Fprintf(stderr, "knock ok remote=%s client=%s method=%s\n", ev.Remote, ev.ClientID, ev.Method)
}
func (textEvents) OnKnockFail(ev relay.KnockFailEvent) {
	_, _ = fmt.Fprintf(stderr, "knock failed remote=%s client=%s reason=%s err=%v\n", ev.Remote, ev.ClientID, ev.Reason, ev.Err)
}
func (textEvents) OnFirewallAllow(ev relay.FirewallEvent) {
	_, _ = fmt.Fprintf(stderr, "firewall allow remote=%s port=%d ttl=%s\n", ev.Remote, ev.Port, ev.TTL)
}
func (textEvents) OnFirewallError(ev relay.FirewallErrorEvent) {
	_, _ = fmt.Fprintf(stderr, "firewall error remote=%s port=%d err=%v\n", ev.Remote, ev.Port, ev.Err)
}
func (textEvents) OnRelayOK(ev relay.RelayEvent) {
	_, _ = fmt.Fprintf(stderr, "relay ok remote=%s client=%s rx=%d tx=%d duration=%s\n", ev.Remote, ev.ClientID, ev.RX, ev.TX, ev.Duration)
}
func (textEvents) OnRelayError(ev relay.RelayErrorEvent) {
	_, _ = fmt.Fprintf(stderr, "relay error remote=%s client=%s stage=%s err=%v\n", ev.Remote, ev.ClientID, ev.Stage, ev.Err)
}
