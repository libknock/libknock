package gate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/firewall"
	"github.com/libknock/libknock/internal/gatewaycore"
	"github.com/libknock/libknock/internal/timerset"
	"github.com/libknock/libknock/knock"
	"github.com/libknock/libknock/netx"
	"github.com/libknock/libknock/observability"
	"github.com/libknock/libknock/relay"
)

type Mode string

const (
	ModeZero          Mode = ""
	AuthOnly          Mode = "auth-only"
	KnockAuthOnly     Mode = "knock-auth-only"
	KnockFirewallAuth Mode = "knock-firewall-auth"
	KnockFirewallOnly Mode = "knock-firewall-only"
)

type Config struct {
	Mode                   Mode
	Listen                 string
	Auth                   auth.ServerConfig
	Listener               netx.ListenerConfig
	Firewall               firewall.Backend
	KnockMethod            string
	KnockListen            string
	KnockPort              int
	KnockClients           []knock.ClientSecret
	KnockTimeWindow        time.Duration
	KnockMaxFrameSize      int
	KnockSequence          knock.SequenceOptions
	KnockNonceTTL          time.Duration
	AllowTTL               time.Duration
	MaxConnectionsPerKnock int
	Events                 observability.GatewayEvents
}

type Gate struct {
	cfg       Config
	store     *relay.KnockSessionStore
	timers    *timerset.Set
	mu        sync.Mutex
	cancel    context.CancelFunc
	knockAddr net.Addr
	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

type managedListener struct {
	net.Listener
	gate *Gate
	once sync.Once
	err  error
}

func (l *managedListener) Close() error {
	l.once.Do(func() {
		if l.Listener != nil {
			l.err = l.Listener.Close()
		}
		if l.gate != nil {
			if err := l.gate.Close(context.Background()); l.err == nil {
				l.err = err
			}
		}
	})
	return l.err
}

type modeCaps struct {
	requireAuth         bool
	requireKnock        bool
	requireFirewall     bool
	defaultNoopFirewall bool
}

var gateModeCaps = map[Mode]modeCaps{
	AuthOnly:          {requireAuth: true, defaultNoopFirewall: true},
	KnockAuthOnly:     {requireAuth: true, requireKnock: true, defaultNoopFirewall: true},
	KnockFirewallAuth: {requireAuth: true, requireKnock: true, requireFirewall: true},
	KnockFirewallOnly: {requireKnock: true, requireFirewall: true},
}

func New(cfg Config) (*Gate, error) {
	cfg, err := validateGateConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Gate{cfg: cfg, store: relay.NewKnockSessionStore(), timers: timerset.New()}, nil
}

func validateGateConfig(cfg Config) (Config, error) {
	if cfg.Mode == "" {
		cfg.Mode = AuthOnly
	}
	caps, ok := gateModeCaps[cfg.Mode]
	if !ok {
		return cfg, fmt.Errorf("unsupported gate mode %q", cfg.Mode)
	}
	if caps.requireAuth && cfg.Auth.Secrets == nil {
		return cfg, auth.ErrMissingSecretResolver
	}
	if caps.requireKnock {
		if err := knock.ValidateClientSecrets(cfg.KnockClients); err != nil {
			return cfg, err
		}
		if cfg.KnockMethod == "" {
			return cfg, errors.New("gate knock method is required")
		}
		if !knock.IsActiveUDPMethod(cfg.KnockMethod) {
			return cfg, fmt.Errorf("gate knock method %q does not support synchronous listener readiness", cfg.KnockMethod)
		}
	}
	if caps.requireFirewall && isNoopFirewall(cfg.Firewall) {
		return cfg, fmt.Errorf("gate %s requires a non-noop firewall backend", cfg.Mode)
	}
	if caps.defaultNoopFirewall && cfg.Firewall == nil {
		cfg.Firewall = firewall.Noop{}
	}
	return cfg, nil
}

func Listen(ctx context.Context, cfg Config) (net.Listener, error) {
	g, err := New(cfg)
	if err != nil {
		return nil, err
	}
	return g.Listen(ctx)
}

func (g *Gate) Listen(ctx context.Context) (net.Listener, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if g.cfg.Listen == "" {
		return nil, errors.New("gate listen address is required")
	}
	ln, err := net.Listen("tcp", g.cfg.Listen)
	if err != nil {
		return nil, err
	}
	return g.Wrap(ctx, ln)
}

func (g *Gate) Wrap(ctx context.Context, ln net.Listener) (net.Listener, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ln == nil {
		return nil, errors.New("gate listener is nil")
	}
	if err := g.configureFirewallPort(gatewaycore.ListenerPort(ln.Addr())); err != nil {
		_ = ln.Close()
		return nil, err
	}
	if err := gatewaycore.ValidateDropUDPKnockPort(g.firewall(), g.cfg.KnockMethod); err != nil {
		_ = ln.Close()
		return nil, err
	}
	switch g.cfg.Mode {
	case AuthOnly:
		wrapped, err := netx.WrapListenerWithConfigE(ln, g.listenerConfig(ln))
		if err != nil {
			_ = ln.Close()
			return nil, err
		}
		return g.manage(wrapped), nil
	case KnockAuthOnly:
		if err := g.startKnockAuthOnly(ctx, ln); err != nil {
			_ = ln.Close()
			return nil, err
		}
		lc := g.listenerConfig(ln)
		lc.Auth.RequireKnock, lc.Auth.KnockStore = true, g.store
		wrapped, err := netx.WrapListenerWithConfigE(ln, lc)
		if err != nil {
			_ = g.Close(context.Background())
			_ = ln.Close()
			return nil, err
		}
		return g.manage(wrapped), nil
	case KnockFirewallAuth:
		if err := g.startKnock(ctx, ln); err != nil {
			_ = ln.Close()
			return nil, err
		}
		lc := g.listenerConfig(ln)
		lc.Auth.RequireKnock, lc.Auth.KnockStore = true, g.store
		wrapped, err := netx.WrapListenerWithConfigE(ln, lc)
		if err != nil {
			_ = g.Close(context.Background())
			_ = ln.Close()
			return nil, err
		}
		return g.manage(wrapped), nil
	case KnockFirewallOnly:
		if err := g.startKnock(ctx, ln); err != nil {
			_ = ln.Close()
			return nil, err
		}
		return g.manage(&firewallOnlyListener{Listener: ln, store: g.store, events: g.cfg.Events}), nil
	default:
		_ = ln.Close()
		return nil, fmt.Errorf("unsupported gate mode %q", g.cfg.Mode)
	}
}

func (g *Gate) Close(ctx context.Context) error {
	g.closeOnce.Do(func() {
		g.mu.Lock()
		cancel := g.cancel
		g.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		g.timers.StopAll()
		g.wg.Wait()
		if g.cfg.Mode == AuthOnly || g.cfg.Mode == KnockAuthOnly || cancel != nil {
			return
		}
		g.closeErr = g.firewall().Cleanup(ctx)
	})
	return g.closeErr
}

func (g *Gate) manage(ln net.Listener) net.Listener { return &managedListener{Listener: ln, gate: g} }

func (g *Gate) configureFirewallPort(port int) error {
	if g.cfg.Mode == AuthOnly || g.cfg.Mode == KnockAuthOnly {
		return nil
	}
	if g.cfg.Auth.ServerPort > 0 {
		port = g.cfg.Auth.ServerPort
	}
	fw, err := gatewaycore.ConfigureFirewallPort(g.firewall(), port)
	if err != nil {
		return err
	}
	g.cfg.Firewall = fw
	return nil
}

func (g *Gate) listenerConfig(ln net.Listener) netx.ListenerConfig {
	lc := g.cfg.Listener
	lc.Auth = g.cfg.Auth.WithDefaults()
	if lc.Auth.ServerPort <= 0 {
		lc.Auth.ServerPort = gatewaycore.ListenerPort(ln.Addr())
	}
	return lc
}

func (g *Gate) startKnockAuthOnly(ctx context.Context, ln net.Listener) error {
	listener, err := g.openKnockListener(ln)
	if err != nil {
		return err
	}
	knockCtx, cancel := context.WithCancel(ctx)
	g.mu.Lock()
	g.cancel = cancel
	g.recordKnockAddrLocked(listener)
	g.mu.Unlock()
	g.wg.Add(2)
	go func() {
		defer g.wg.Done()
		<-knockCtx.Done()
		_ = listener.Close()
		_ = ln.Close()
	}()
	go func() {
		defer g.wg.Done()
		if err := listener.Serve(knockCtx, g.knockSessionOnlyHandler(ln)); err != nil && knockCtx.Err() == nil {
			gatewaycore.EventEmitter{Sink: g.cfg.Events}.KnockFail(observability.KnockFailEvent{Reason: "listen_error", Err: err})
			_ = ln.Close()
		}
	}()
	return nil
}

func (g *Gate) startKnock(ctx context.Context, ln net.Listener) error {
	fw := g.firewall()
	if err := gatewaycore.InitFirewall(ctx, fw); err != nil {
		return err
	}
	listener, err := g.openKnockListener(ln)
	if err != nil {
		_ = gatewaycore.CleanupFirewall(context.Background(), fw)
		return err
	}
	knockCtx, cancel := context.WithCancel(ctx)
	g.mu.Lock()
	g.cancel = cancel
	g.recordKnockAddrLocked(listener)
	g.mu.Unlock()
	g.wg.Add(2)
	go func() {
		defer g.wg.Done()
		<-knockCtx.Done()
		_ = gatewaycore.CleanupFirewall(context.Background(), fw)
		_ = listener.Close()
		_ = ln.Close()
	}()
	go func() {
		defer g.wg.Done()
		if err := listener.Serve(knockCtx, g.knockHandler(knockCtx, ln)); err != nil && knockCtx.Err() == nil {
			gatewaycore.EventEmitter{Sink: g.cfg.Events}.KnockFail(observability.KnockFailEvent{Reason: "listen_error", Err: err})
			_ = ln.Close()
		}
	}()
	return nil
}

func (g *Gate) knockSessionOnlyHandler(ln net.Listener) knock.Handler {
	return func(ev knock.Event) {
		remote, ok := netip.AddrFromSlice(ev.SourceIP)
		if !ok {
			gatewaycore.EventEmitter{Sink: g.cfg.Events}.KnockFail(observability.KnockFailEvent{ClientID: ev.ClientID, Reason: "invalid_source_ip"})
			return
		}
		ttl := g.cfg.AllowTTL
		if ttl <= 0 {
			ttl = time.Minute
		}
		port := g.cfg.Auth.ServerPort
		if port <= 0 {
			port = gatewaycore.ListenerPort(ln.Addr())
		}
		uses := g.cfg.MaxConnectionsPerKnock
		g.store.AddSessionForPort(remote, ev.ClientID, ev.SessionID, port, ttl, uses)
		gatewaycore.EventEmitter{Sink: g.cfg.Events}.KnockOK(observability.KnockEvent{Remote: remote, ClientID: ev.ClientID, Method: ev.Method, Parts: ev.Parts, TTL: ttl})
		g.timers.AfterFunc(ttl, func() { g.store.ExpireForPort(remote, ev.ClientID, port, time.Now()) })
	}
}

func (g *Gate) knockHandler(ctx context.Context, ln net.Listener) knock.Handler {
	return func(ev knock.Event) {
		remote, ok := netip.AddrFromSlice(ev.SourceIP)
		if !ok {
			gatewaycore.EventEmitter{Sink: g.cfg.Events}.KnockFail(observability.KnockFailEvent{ClientID: ev.ClientID, Reason: "invalid_source_ip"})
			return
		}
		ttl := g.cfg.AllowTTL
		if ttl <= 0 {
			ttl = time.Minute
		}
		port := g.cfg.Auth.ServerPort
		if port <= 0 {
			port = gatewaycore.ListenerPort(ln.Addr())
		}
		fw := g.firewall()
		if err := gatewaycore.AllowFirewall(ctx, fw, remote, port, ttl, g.cfg.Events); err != nil {
			gatewaycore.EventEmitter{Sink: g.cfg.Events}.KnockFail(observability.KnockFailEvent{Remote: remote, ClientID: ev.ClientID, Reason: "firewall_allow_failed", Err: err})
			return
		}
		uses := g.cfg.MaxConnectionsPerKnock
		storeClientID := ev.ClientID
		sessionID := ev.SessionID
		if g.cfg.Mode == KnockFirewallOnly {
			storeClientID = firewallOnlyClientID
			sessionID = nil
			g.store.AddSession(remote, storeClientID, sessionID, ttl, uses)
		} else {
			g.store.AddSessionForPort(remote, storeClientID, sessionID, port, ttl, uses)
		}
		leaseID := g.store.MarkFirewall(remote, port, ttl)
		gatewaycore.EventEmitter{Sink: g.cfg.Events}.KnockOK(observability.KnockEvent{Remote: remote, ClientID: ev.ClientID, Method: ev.Method, Parts: ev.Parts, TTL: ttl})
		g.timers.AfterFunc(ttl, func() {
			g.store.Expire(remote, storeClientID, time.Now())
			if g.store.ExpireFirewall(remote, port, leaseID, time.Now()) && gatewaycore.ShouldManualRevoke(fw) {
				gatewaycore.RevokeFirewall(ctx, fw, remote, port, g.cfg.Events)
			}
		})
	}
}

func (g *Gate) openKnockListener(ln net.Listener) (knock.KnockListener, error) {
	opts := knock.ListenOptions{Port: gatewaycore.ListenerPort(ln.Addr()), KnockPort: g.cfg.KnockPort, Clients: g.cfg.KnockClients, TimeWindow: g.cfg.KnockTimeWindow, MaxFrameSize: g.cfg.KnockMaxFrameSize, RequireSessionID: g.cfg.Mode == KnockAuthOnly || g.cfg.Mode == KnockFirewallAuth, ReplayCache: auth.NewMemoryReplayCache(5 * time.Minute), Sequence: g.cfg.KnockSequence, NonceTTL: g.cfg.KnockNonceTTL}
	if g.cfg.Auth.ServerPort > 0 {
		opts.Port = g.cfg.Auth.ServerPort
	}
	switch g.cfg.KnockMethod {
	case knock.UDPMethod:
		return knock.NewUDPListener(gatewaycore.DefaultString(g.cfg.KnockListen, gatewaycore.UDPListenForKnockPort(ln.Addr(), g.cfg.KnockPort)), opts)
	case knock.UDPSeqMethod:
		return knock.NewUDPSequenceListener(gatewaycore.DefaultString(g.cfg.KnockListen, gatewaycore.UDPListenForKnockPort(ln.Addr(), g.cfg.KnockPort)), opts)
	default:
		return nil, fmt.Errorf("gate knock method %q does not support synchronous listener readiness", g.cfg.KnockMethod)
	}
}

func (g *Gate) recordKnockAddrLocked(listener knock.KnockListener) {
	if withAddr, ok := listener.(interface{ Addr() net.Addr }); ok {
		g.knockAddr = withAddr.Addr()
	}
}

func (g *Gate) firewall() firewall.Backend {
	if g.cfg.Firewall != nil {
		return g.cfg.Firewall
	}
	return firewall.Noop{}
}

func isNoopFirewall(fw firewall.Backend) bool {
	if fw == nil {
		return true
	}
	switch fw.(type) {
	case firewall.Noop, *firewall.Noop:
		return true
	default:
		return false
	}
}
