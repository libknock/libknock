package netx

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/libknock/libknock/auth"
)

const (
	DefaultMaxPendingAuth = 128
	DefaultMaxAuthWorkers = 32
)

var ErrNilListener = errors.New("nil listener")

type ListenerConfig struct {
	Auth           auth.ServerConfig
	MaxPendingAuth int
	MaxAuthWorkers int
	Events         EventSink
}

type errorListener struct {
	net.Listener
	err error
}

func (l errorListener) Accept() (net.Conn, error) { return nil, l.err }
func (l errorListener) Close() error {
	if l.Listener != nil {
		return l.Listener.Close()
	}
	return nil
}
func (l errorListener) Addr() net.Addr {
	if l.Listener != nil {
		return l.Listener.Addr()
	}
	return nil
}

type AuthenticatedListener struct {
	net.Listener
	Config auth.ServerConfig

	listenerConfig ListenerConfig
	server         *auth.Server
	ctx            context.Context
	cancel         context.CancelFunc
	ready          chan net.Conn
	pending        chan net.Conn
	done           chan struct{}
	closeOnce      sync.Once
	doneOnce       sync.Once
	readyOnce      sync.Once
	wg             sync.WaitGroup
	mu             sync.Mutex
	err            error
	inFlight       map[net.Conn]struct{}
}

func NewListener(ln net.Listener, cfg ListenerConfig) (*AuthenticatedListener, error) {
	l, err := WrapListenerWithConfigE(ln, cfg)
	if err != nil {
		return nil, err
	}
	authenticated, ok := l.(*AuthenticatedListener)
	if !ok {
		return nil, errors.New("unexpected listener type")
	}
	return authenticated, nil
}

func WrapListener(ln net.Listener, cfg auth.ServerConfig) net.Listener {
	l, err := WrapListenerWithConfigE(ln, ListenerConfig{Auth: cfg})
	if err != nil {
		return errorListener{Listener: ln, err: err}
	}
	return l
}

func WrapListenerWithConfig(ln net.Listener, cfg ListenerConfig) net.Listener {
	l, err := WrapListenerWithConfigE(ln, cfg)
	if err != nil {
		return errorListener{Listener: ln, err: err}
	}
	return l
}

func WrapListenerWithConfigE(ln net.Listener, cfg ListenerConfig) (net.Listener, error) {
	if ln == nil {
		return nil, ErrNilListener
	}
	cfg = cfg.withDefaults()
	server, err := auth.NewServer(cfg.Auth)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &AuthenticatedListener{Listener: ln, Config: cfg.Auth, listenerConfig: cfg, server: server, ctx: ctx, cancel: cancel, ready: make(chan net.Conn), pending: make(chan net.Conn, cfg.MaxPendingAuth), done: make(chan struct{}), inFlight: make(map[net.Conn]struct{})}
	l.start()
	return l, nil
}

func (c ListenerConfig) withDefaults() ListenerConfig {
	c.Auth = c.Auth.WithDefaults()
	if c.Auth.ReplayCache == nil {
		// Listener-owned auth keeps one replay cache for all accepted connections; per-connection caches would let replayed frames through.
		c.Auth.ReplayCache = auth.NewMemoryReplayCache(c.Auth.TimeWindow * 2)
	}
	if c.MaxPendingAuth <= 0 {
		c.MaxPendingAuth = DefaultMaxPendingAuth
	}
	if c.MaxAuthWorkers <= 0 {
		c.MaxAuthWorkers = DefaultMaxAuthWorkers
	}
	return c
}

func (l *AuthenticatedListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ready
	if !ok {
		return nil, l.acceptErr()
	}
	return conn, nil
}

func (l *AuthenticatedListener) Close() error {
	if l == nil {
		return ErrNilListener
	}
	var err error
	l.closeOnce.Do(func() {
		l.setErr(net.ErrClosed)
		l.cancel()
		l.closeDone()
		if l.Listener != nil {
			err = l.Listener.Close()
		}
		l.closeInFlight()
	})
	return err
}

func (l *AuthenticatedListener) start() {
	l.wg.Add(1)
	go l.acceptLoop()
	for range l.listenerConfig.MaxAuthWorkers {
		l.wg.Add(1)
		go l.authWorker()
	}
	go func() {
		l.wg.Wait()
		l.readyOnce.Do(func() { close(l.ready) })
	}()
}

func (l *AuthenticatedListener) acceptLoop() {
	defer l.wg.Done()
	defer close(l.pending)
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			l.setErr(err)
			l.closeDone()
			return
		}
		select {
		case l.pending <- conn:
		case <-l.done:
			_ = conn.Close()
			return
		default:
			l.reportAuthDrop(conn.RemoteAddr(), ErrAuthBackpressure)
			_ = conn.Close()
		}
	}
}

func (l *AuthenticatedListener) reportAuthDrop(remote net.Addr, reason error) {
	if l.listenerConfig.Events != nil {
		l.listenerConfig.Events.OnAuthDrop(remote, reason, len(l.pending))
	}
}

func (l *AuthenticatedListener) authWorker() {
	defer l.wg.Done()
	for conn := range l.pending {
		l.trackInFlight(conn)
		clean, err := l.authenticateConn(conn)
		l.untrackInFlight(conn)
		if err != nil {
			continue
		}
		select {
		case l.ready <- clean:
		case <-l.done:
			_ = clean.Close()
			return
		}
	}
}

func (l *AuthenticatedListener) authenticateConn(conn net.Conn) (net.Conn, error) {
	authCtx := l.ctx
	cancel := func() {}
	if l.listenerConfig.Auth.AuthTimeout > 0 {
		authCtx, cancel = context.WithTimeout(l.ctx, l.listenerConfig.Auth.AuthTimeout)
	}
	defer cancel()
	var clean net.Conn
	var err error
	if l.server != nil {
		clean, _, err = l.server.Auth(authCtx, conn)
	} else {
		clean, _, err = auth.ServerAuth(authCtx, conn, l.listenerConfig.Auth)
	}
	return clean, err
}

func (l *AuthenticatedListener) setErr(err error) {
	if err == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err == nil {
		l.err = err
	}
}

func (l *AuthenticatedListener) acceptErr() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	return net.ErrClosed
}

func (l *AuthenticatedListener) trackInFlight(conn net.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.done:
		_ = conn.Close()
	default:
		l.inFlight[conn] = struct{}{}
	}
}

func (l *AuthenticatedListener) untrackInFlight(conn net.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.inFlight, conn)
}

func (l *AuthenticatedListener) closeDone() {
	l.doneOnce.Do(func() { close(l.done) })
}

func (l *AuthenticatedListener) closeInFlight() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for conn := range l.inFlight {
		_ = conn.SetDeadline(time.Now())
		_ = conn.Close()
	}
}
