package relay

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/firewall"
	"github.com/libknock/libknock/internal/gatewaycore"
	"github.com/libknock/libknock/internal/timerset"
)

func (g Gateway) Run(ctx context.Context) error {
	return g.run(ctx)
}

func (g *Gateway) run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if g.Listen == "" {
		return errors.New("relay gateway listen address is required")
	}
	if g.Upstream == "" {
		return errors.New("relay gateway upstream address is required")
	}
	if g.RemoveAfterAuth && g.MaxConnectionsPerKnock > 1 {
		return errors.New("remove_after_auth=true conflicts with max_connections_per_knock > 1")
	}
	fw := g.Firewall
	if fw == nil {
		fw = firewall.Noop{}
	}
	if err := validateRelayFirewallMode(fw, g.KnockMethod); err != nil {
		return err
	}
	if err := gatewaycore.ValidateDropUDPKnockPort(fw, g.KnockMethod); err != nil {
		return err
	}
	store, _ := g.Auth.KnockStore.(*KnockSessionStore)
	if store == nil {
		store = NewKnockSessionStore()
	}
	authCfg := g.Auth
	if authCfg.RequireKnock || g.KnockMethod != "" {
		authCfg.RequireKnock, authCfg.KnockStore = true, store
	}
	authCfg = authCfg.WithDefaults()
	if authCfg.ReplayCache == nil {
		authCfg.ReplayCache = auth.NewMemoryReplayCache(authCfg.TimeWindow * 2)
	}
	ln, err := net.Listen("tcp", g.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	protectedPort := authCfg.ServerPort
	if protectedPort <= 0 {
		protectedPort = gatewaycore.ListenerPort(ln.Addr())
		authCfg.ServerPort = protectedPort
	}
	fw, err = gatewaycore.ConfigureFirewallPort(fw, protectedPort)
	if err != nil {
		return err
	}
	if err := gatewaycore.InitFirewall(ctx, fw); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	timers := timerset.New()
	defer timers.StopAll()
	defer func() { _ = gatewaycore.CleanupFirewallDetached(fw) }()
	var childErr firstChildError
	var wg sync.WaitGroup
	if g.KnockMethod != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := g.listenKnock(runCtx, fw, store, protectedPort, timers)
			if err != nil && runCtx.Err() == nil {
				childErr.store(err)
				g.emitRelayError(RelayErrorEvent{Stage: "knock", Err: err})
				_ = ln.Close()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-runCtx.Done()
		_ = ln.Close()
	}()
	pending := make(chan net.Conn, g.maxPendingAuth())
	for range g.maxAuthWorkers() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for conn := range pending {
				g.handleConn(runCtx, conn, authCfg, fw, store)
			}
		}()
	}
	defer func() {
		cancel()
		close(pending)
		wg.Wait()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if runCtx.Err() != nil {
				return nil
			}
			if e := childErr.load(); e != nil {
				return e
			}
			return err
		}
		select {
		case pending <- conn:
		case <-runCtx.Done():
			_ = conn.Close()
			return nil
		default:
			_ = conn.Close()
			g.emitRelayError(RelayErrorEvent{
				Remote: conn.RemoteAddr(),
				Stage:  "pending_full",
				Err:    errors.New("auth pending queue full"),
			})
		}
	}
}

type firstChildError struct {
	mu  sync.Mutex
	err error
}

func (e *firstChildError) store(err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err == nil {
		e.err = err
	}
}

func (e *firstChildError) load() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}
