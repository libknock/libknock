package relay

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/firewall"
	"github.com/libknock/libknock/internal/acceptx"
	"github.com/libknock/libknock/internal/gatewaycore"
	"github.com/libknock/libknock/internal/iplimit"
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
	active := newActiveConnections()
	var wg sync.WaitGroup
	if g.KnockMethod != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := g.listenKnock(runCtx, fw, store, protectedPort, timers)
			if err != nil && runCtx.Err() == nil {
				childErr.store(err)
				g.emitRelayError(RelayErrorEvent{Stage: "knock", Err: err})
				cancel()
				_ = ln.Close()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-runCtx.Done()
		_ = ln.Close()
		active.CloseAll()
	}()
	pending := make(chan pendingConn, g.maxPendingAuth())
	perSource := iplimit.New(g.maxPendingAuthPerSource())
	var dropped atomic.Int64
	for range g.maxAuthWorkers() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range pending {
				conn := item.conn
				// Only the auth phase runs on the bounded worker pool. A
				// successfully authenticated session is relayed on its own
				// goroutine so long-lived sessions cannot starve new auths.
				session := g.authenticateConn(runCtx, conn, authCfg, fw, store)
				item.release()
				if session == nil {
					active.Remove(conn)
					continue
				}
				wg.Add(1)
				go func(conn net.Conn, session *authenticatedSession) {
					defer wg.Done()
					defer active.Remove(conn)
					g.relaySession(runCtx, session)
				}(conn, session)
			}
		}()
	}
	defer func() {
		cancel()
		close(pending)
		wg.Wait()
	}()
	var backoff acceptx.Backoff
	for {
		conn, err := ln.Accept()
		if err != nil {
			if e := childErr.load(); e != nil {
				return e
			}
			if runCtx.Err() != nil {
				return nil
			}
			// Back off and retry transient errors such as EMFILE instead of
			// tearing down the whole gateway.
			if acceptx.IsTemporary(err) {
				if acceptx.Sleep(backoff.Next(), runCtx.Done()) {
					continue
				}
				if e := childErr.load(); e != nil {
					return e
				}
				return nil
			}
			return err
		}
		backoff.Reset()
		release, ok := perSource.Acquire(conn.RemoteAddr())
		if !ok {
			_ = conn.Close()
			g.emitRelayError(RelayErrorEvent{
				Remote:       conn.RemoteAddr(),
				Stage:        "source_limit",
				Err:          errors.New("auth per-source pending limit reached"),
				DroppedCount: dropped.Add(1),
				Pending:      len(pending),
			})
			continue
		}
		active.Add(conn)
		select {
		case pending <- pendingConn{conn: conn, release: release}:
		case <-runCtx.Done():
			release()
			active.Remove(conn)
			_ = conn.Close()
			if e := childErr.load(); e != nil {
				return e
			}
			return nil
		default:
			release()
			active.Remove(conn)
			_ = conn.Close()
			g.emitRelayError(RelayErrorEvent{
				Remote:       conn.RemoteAddr(),
				Stage:        "pending_full",
				Err:          errors.New("auth pending queue full"),
				DroppedCount: dropped.Add(1),
				Pending:      len(pending),
			})
		}
	}
}

type pendingConn struct {
	conn    net.Conn
	release func()
}

type activeConnections struct {
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

func newActiveConnections() *activeConnections {
	return &activeConnections{conns: make(map[net.Conn]struct{})}
}

func (c *activeConnections) Add(conn net.Conn) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return
	}
	c.conns[conn] = struct{}{}
	c.mu.Unlock()
}

func (c *activeConnections) Remove(conn net.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.conns, conn)
}

func (c *activeConnections) CloseAll() {
	c.mu.Lock()
	c.closed = true
	conns := make([]net.Conn, 0, len(c.conns))
	for conn := range c.conns {
		conns = append(conns, conn)
	}
	c.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
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
