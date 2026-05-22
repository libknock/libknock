package gate

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/firewall"
	"github.com/libknock/libknock/internal/gatewaycore"
	"github.com/libknock/libknock/knock"
	"github.com/libknock/libknock/netx"
	"github.com/libknock/libknock/observability"
	"github.com/libknock/libknock/relay"
)

func TestAuthOnlyGateWrapsAuthenticatedListener(t *testing.T) {
	secret := testSecret()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(Config{Mode: AuthOnly, Auth: auth.ServerConfig{ServerPort: mustPort(t, raw.Addr()), Secrets: auth.StaticSecrets{"client": secret}, AuthTimeout: time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := g.Wrap(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			serverErr <- err
			return
		}
		_, err = io.WriteString(conn, "echo:"+line)
		serverErr <- err
	}()
	d := netx.Dialer{Config: auth.ClientConfig{ClientID: "client", Secret: secret, ServerPort: mustPort(t, raw.Addr())}}
	conn, err := d.DialContext(context.Background(), "tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "hello\n"); err != nil {
		t.Fatal(err)
	}
	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if got != "echo:hello\n" {
		t.Fatalf("got %q", got)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestKnockFirewallOnlyRequiresKnockSession(t *testing.T) {
	secret := testSecret()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := Listen(ctx, Config{Mode: KnockFirewallOnly, Listen: "127.0.0.1:0", Firewall: &recordingFirewall{}, KnockMethod: knock.UDPMethod, KnockListen: "127.0.0.1:0", KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: secret}}, AllowTTL: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	denied, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = denied.Close()
	accepted := make(chan net.Conn, 1)
	go func() { conn, _ := ln.Accept(); accepted <- conn }()
	select {
	case conn := <-accepted:
		if conn != nil {
			conn.Close()
			t.Fatal("unauthorized connection accepted")
		}
	case <-time.After(100 * time.Millisecond):
	}
}

func testSecret() []byte { return []byte("0123456789abcdef0123456789abcdef") }
func mustPort(t *testing.T, addr net.Addr) int {
	t.Helper()
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr is %T", addr)
	}
	return tcp.Port
}

func TestGateWrapInjectsListenerPortIntoFirewall(t *testing.T) {
	fw := firewall.NewScript(firewall.Config{Backend: "script", Script: firewall.ScriptConfig{AllowCmd: "true", RevokeCmd: "true", CleanupCmd: "true"}})
	g, err := New(Config{Mode: KnockFirewallOnly, Firewall: fw, KnockMethod: knock.UDPMethod, KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: testSecret()}}, AllowTTL: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wrapped, err := g.Wrap(ctx, ln)
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	configured, ok := g.cfg.Firewall.(*firewall.Script)
	if !ok {
		t.Fatalf("firewall type = %T", g.cfg.Firewall)
	}
	if configured.Config().Port != gatewaycore.ListenerPort(wrapped.Addr()) {
		t.Fatalf("firewall port = %d, want listener port %d", configured.Config().Port, gatewaycore.ListenerPort(wrapped.Addr()))
	}
}

func TestFirewallModesRejectNilOrNoopFirewall(t *testing.T) {
	for _, tc := range []Config{
		{Mode: KnockFirewallAuth, Auth: auth.ServerConfig{Secrets: auth.StaticSecrets{"client": testSecret()}}, KnockMethod: knock.UDPMethod, KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: testSecret()}}},
		{Mode: KnockFirewallOnly, KnockMethod: knock.UDPMethod, KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: testSecret()}}},
		{Mode: KnockFirewallAuth, Firewall: firewall.Noop{}, Auth: auth.ServerConfig{Secrets: auth.StaticSecrets{"client": testSecret()}}, KnockMethod: knock.UDPMethod, KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: testSecret()}}},
		{Mode: KnockFirewallOnly, Firewall: firewall.Noop{}, KnockMethod: knock.UDPMethod, KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: testSecret()}}},
	} {
		if _, err := New(tc); err == nil {
			t.Fatalf("New(%s) succeeded with nil/noop firewall", tc.Mode)
		}
	}
}

func TestGateWrapRejectsDropUDPKnockPortForActiveUDP(t *testing.T) {
	fw := firewall.NewIptables(firewall.Config{Port: 443, DropUDPKnockPort: true})
	g, err := New(Config{Mode: KnockFirewallOnly, Firewall: fw, KnockMethod: knock.UDPMethod, KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: testSecret()}}, AllowTTL: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Wrap(context.Background(), ln); err == nil {
		_ = ln.Close()
		t.Fatal("Wrap accepted drop_udp_knock_port with active UDP method")
	}
}

func TestUDPListenForKnockPortUsesConfiguredPort(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000}
	if got := gatewaycore.UDPListenForKnockPort(addr, 10000); got != "127.0.0.1:10000" {
		t.Fatalf("udp listen = %q, want 127.0.0.1:10000", got)
	}
	if got := gatewaycore.UDPListenForKnockPort(addr, 0); got != "127.0.0.1:9000" {
		t.Fatalf("udp listen fallback = %q, want 127.0.0.1:9000", got)
	}
}

type countingFirewall struct {
	mu      sync.Mutex
	init    int
	allow   int
	revoke  int
	cleanup int
	config  firewall.Config
}

func (f *countingFirewall) Name() string { return "counting" }
func (f *countingFirewall) Init(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init++
	return nil
}
func (f *countingFirewall) Allow(context.Context, netip.Addr, int, time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allow++
	return nil
}
func (f *countingFirewall) Revoke(context.Context, netip.Addr, int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoke++
	return nil
}
func (f *countingFirewall) Cleanup(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleanup++
	return nil
}
func (f *countingFirewall) counts() (int, int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.init, f.allow, f.revoke, f.cleanup
}
func (f *countingFirewall) Config() firewall.Config { return f.config }
func (f *countingFirewall) WithConfig(cfg firewall.Config) (firewall.Backend, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.config = cfg
	return f, nil
}

type gateKnockRecorder struct {
	mu        sync.Mutex
	knocks    int
	fails     int
	authOK    int
	authFails []error
}

func (r *gateKnockRecorder) OnKnockOK(observability.KnockEvent) {
	r.mu.Lock()
	r.knocks++
	r.mu.Unlock()
}
func (r *gateKnockRecorder) OnKnockFail(observability.KnockFailEvent) {
	r.mu.Lock()
	r.fails++
	r.mu.Unlock()
}
func (r *gateKnockRecorder) OnFirewallAllow(observability.FirewallEvent)      {}
func (r *gateKnockRecorder) OnFirewallError(observability.FirewallErrorEvent) {}
func (r *gateKnockRecorder) OnRelayOK(observability.RelayEvent)               {}
func (r *gateKnockRecorder) OnRelayError(observability.RelayErrorEvent)       {}
func (r *gateKnockRecorder) OnAccept(net.Addr)                                {}
func (r *gateKnockRecorder) OnAuthOK(auth.PeerInfo) {
	r.mu.Lock()
	r.authOK++
	r.mu.Unlock()
}
func (r *gateKnockRecorder) OnAuthFail(_ net.Addr, reason error) {
	r.mu.Lock()
	r.authFails = append(r.authFails, reason)
	r.mu.Unlock()
}
func (r *gateKnockRecorder) OnReplay(net.Addr, uint64)                    {}
func (r *gateKnockRecorder) OnReplayCacheFull(net.Addr, uint64, int, int) {}
func (r *gateKnockRecorder) OnRateLimited(net.Addr)                       {}
func (r *gateKnockRecorder) waitKnocks(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		got := r.knocks
		r.mu.Unlock()
		if got >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("observed %d knocks, want %d", r.knocks, want)
}

func TestKnockAuthOnlyValidation(t *testing.T) {
	secret := testSecret()
	if _, err := New(Config{Mode: KnockAuthOnly, KnockMethod: knock.UDPMethod, KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: secret}}}); err == nil {
		t.Fatal("KnockAuthOnly accepted missing auth secrets")
	}
	if _, err := New(Config{Mode: KnockAuthOnly, Auth: auth.ServerConfig{Secrets: auth.StaticSecrets{"client": secret}}, KnockMethod: knock.UDPMethod}); err == nil {
		t.Fatal("KnockAuthOnly accepted missing knock clients")
	}
	if _, err := New(Config{Mode: KnockAuthOnly, Auth: auth.ServerConfig{Secrets: auth.StaticSecrets{"client": secret}}, KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: secret}}}); err == nil {
		t.Fatal("KnockAuthOnly accepted missing knock method")
	}
	if _, err := New(Config{Mode: KnockAuthOnly, Auth: auth.ServerConfig{Secrets: auth.StaticSecrets{"client": secret}}, Firewall: firewall.Noop{}, KnockMethod: knock.UDPMethod, KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: secret}}}); err != nil {
		t.Fatalf("KnockAuthOnly rejected noop firewall: %v", err)
	}
	if _, err := New(Config{Mode: KnockAuthOnly, Auth: auth.ServerConfig{Secrets: auth.StaticSecrets{"client": secret}}, KnockMethod: knock.UDPMethod, KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: secret}}}); err != nil {
		t.Fatalf("KnockAuthOnly rejected nil firewall: %v", err)
	}
}

func TestKnockAuthOnlyDoesNotUseFirewall(t *testing.T) {
	secret := testSecret()
	fw := &countingFirewall{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, err := New(Config{Mode: KnockAuthOnly, Auth: auth.ServerConfig{Secrets: auth.StaticSecrets{"client": secret}}, Firewall: fw, KnockMethod: knock.UDPMethod, KnockListen: "127.0.0.1:0", KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: secret}}, AllowTTL: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := g.Wrap(ctx, ln)
	if err != nil {
		t.Fatal(err)
	}
	_ = wrapped.Close()
	cancel()
	if init, allow, revoke, cleanup := fw.counts(); init != 0 || allow != 0 || revoke != 0 || cleanup != 0 {
		t.Fatalf("firewall calls = init:%d allow:%d revoke:%d cleanup:%d, want all zero", init, allow, revoke, cleanup)
	}
}

func TestManagedListenerCloseStopsGateResources(t *testing.T) {
	secret := testSecret()
	fw := &countingFirewall{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, err := New(Config{Mode: KnockFirewallAuth, Listen: "127.0.0.1:0", Auth: auth.ServerConfig{Secrets: auth.StaticSecrets{"client": secret}}, Firewall: fw, KnockMethod: knock.UDPMethod, KnockListen: "127.0.0.1:0", KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: secret}}, AllowTTL: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := g.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	knockAddr := g.knockAddr.String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if _, allow, revoke, cleanup := fw.counts(); allow != 0 || revoke != 0 || cleanup != 1 {
		t.Fatalf("firewall calls after Close = allow:%d revoke:%d cleanup:%d, want allow/revoke 0 cleanup 1", allow, revoke, cleanup)
	}
	conn, err := net.ListenPacket("udp", knockAddr)
	if err != nil {
		t.Fatalf("knock listener still bound at %s: %v", knockAddr, err)
	}
	_ = conn.Close()
}

func TestKnockAuthOnlyRequiresPriorKnock(t *testing.T) {
	secret := testSecret()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &gateKnockRecorder{}
	g, err := New(Config{Mode: KnockAuthOnly, Listen: "127.0.0.1:0", Auth: auth.ServerConfig{Secrets: auth.StaticSecrets{"client": secret}, Events: rec, ServerProof: true}, KnockMethod: knock.UDPMethod, KnockListen: "127.0.0.1:0", KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: secret}}, AllowTTL: time.Second, Events: rec})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := g.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err == nil {
				accepted <- conn
			}
		}
	}()
	unauthConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ClientAuth(context.Background(), unauthConn, auth.ClientConfig{ClientID: "client", Secret: secret, ServerPort: mustPort(t, ln.Addr()), AuthTimeout: 200 * time.Millisecond, RequireServerProof: true}); err == nil {
		t.Fatal("auth succeeded before knock")
	}
	select {
	case conn := <-accepted:
		conn.Close()
		t.Fatal("application received pre-knock connection")
	case <-time.After(150 * time.Millisecond):
	}
	sessionID := []byte("manual-session-1")
	if err := knock.SendUDP(context.Background(), knock.SendOptions{ServerAddr: g.knockAddr.String(), ClientID: "client", Secret: secret, ServerPort: mustPort(t, ln.Addr()), SessionID: sessionID}); err != nil {
		t.Fatal(err)
	}
	rec.waitKnocks(t, 1)
	postKnock := netx.Dialer{Config: auth.ClientConfig{ClientID: "client", Secret: secret, ServerPort: mustPort(t, ln.Addr()), RequireServerProof: true, SessionID: sessionID}}
	conn, err := postKnock.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("auth after knock failed: %v", err)
	}
	defer conn.Close()
	select {
	case app := <-accepted:
		app.Close()
	case <-time.After(time.Second):
		rec.mu.Lock()
		authOK, authFails := rec.authOK, append([]error(nil), rec.authFails...)
		rec.mu.Unlock()
		t.Fatalf("application did not receive post-knock authenticated connection; authOK=%d authFails=%v", authOK, authFails)
	}
}

func TestKnockAuthOnlyDialerSessionID(t *testing.T) {
	secret := testSecret()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &gateKnockRecorder{}
	g, err := New(Config{Mode: KnockAuthOnly, Listen: "127.0.0.1:0", Auth: auth.ServerConfig{Secrets: auth.StaticSecrets{"client": secret}, ServerProof: true, Events: rec}, KnockMethod: knock.UDPMethod, KnockListen: "127.0.0.1:0", KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: secret}}, AllowTTL: time.Second, MaxConnectionsPerKnock: 1, Events: rec})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := g.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err == nil {
				accepted <- conn
			}
		}
	}()
	baseKnock := knock.SendOptions{ServerAddr: g.knockAddr.String(), ClientID: "client", Secret: secret, ServerPort: mustPort(t, ln.Addr())}
	dialer := netx.Dialer{Config: auth.ClientConfig{ClientID: "client", Secret: secret, ServerPort: mustPort(t, ln.Addr()), RequireServerProof: true, Knock: &testKnockSender{method: knock.UDPMethod, opts: baseKnock, after: func() { rec.waitKnocks(t, 1) }}}}
	conn, err := dialer.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial with bound knock failed: %v", err)
	}
	conn.Close()
	select {
	case app := <-accepted:
		app.Close()
	case <-time.After(time.Second):
		t.Fatal("application did not receive authenticated dialer connection")
	}
	badKnock := baseKnock
	badKnock.SessionID = []byte("fixed-knock-session-1")
	badDialer := netx.Dialer{Config: auth.ClientConfig{ClientID: "client", Secret: secret, ServerPort: mustPort(t, ln.Addr()), RequireServerProof: true, Knock: testFixedSessionKnockSender{method: knock.UDPMethod, opts: badKnock, after: func() { rec.waitKnocks(t, 2) }}}}
	if conn, err := badDialer.DialContext(context.Background(), "tcp", ln.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("dial succeeded with mismatched knock/auth session id")
	}
}

type testKnockSender struct {
	method string
	opts   knock.SendOptions
	after  func()
}

func (s *testKnockSender) SetSessionID(sessionID []byte) {
	s.opts.SessionID = append([]byte(nil), sessionID...)
}
func (s *testKnockSender) Knock(ctx context.Context) error {
	if err := knock.SendMethod(ctx, s.method, s.opts); err != nil {
		return err
	}
	if s.after != nil {
		s.after()
	}
	return nil
}

type testFixedSessionKnockSender struct {
	method string
	opts   knock.SendOptions
	after  func()
}

func (s testFixedSessionKnockSender) Knock(ctx context.Context) error {
	if err := knock.SendMethod(ctx, s.method, s.opts); err != nil {
		return err
	}
	if s.after != nil {
		s.after()
	}
	return nil
}

func TestKnockAuthOnlySessionTTLAndConnectionLimit(t *testing.T) {
	remote := netip.MustParseAddr("127.0.0.1")
	store := relay.NewKnockSessionStore()
	port := 9443
	store.AddSessionForPort(remote, "client", nil, port, 20*time.Millisecond, 1)
	time.Sleep(30 * time.Millisecond)
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}, ServerPort: port}, &net.TCPAddr{IP: remote.AsSlice(), Port: 50000}); err == nil {
		t.Fatal("expired knock session was accepted")
	}
	store.AddSessionForPort(remote, "client", nil, port, time.Minute, 1)
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "other"}, ServerPort: port}, &net.TCPAddr{IP: remote.AsSlice(), Port: 50000}); err == nil {
		t.Fatal("mismatched client consumed knock session")
	}
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}, ServerPort: port}, &net.TCPAddr{IP: remote.AsSlice(), Port: 50000}); err != nil {
		t.Fatalf("first use failed: %v", err)
	}
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}, ServerPort: port}, &net.TCPAddr{IP: remote.AsSlice(), Port: 50001}); err == nil {
		t.Fatal("second use succeeded for one-use knock session")
	}
	store.AddSessionForPort(remote, "client", nil, port, time.Minute, 2)
	for i := 0; i < 2; i++ {
		if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}, ServerPort: port}, &net.TCPAddr{IP: remote.AsSlice(), Port: 50000 + i}); err != nil {
			t.Fatalf("use %d failed: %v", i+1, err)
		}
	}
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}, ServerPort: port}, &net.TCPAddr{IP: remote.AsSlice(), Port: 50003}); err == nil {
		t.Fatal("third use succeeded for two-use knock session")
	}
}

func TestKnockAuthOnlyRejectsWrongSecretWrongSessionAndExpiredSession(t *testing.T) {
	secret := testSecret()
	wrong := []byte("abcdef0123456789abcdef0123456789")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &gateKnockRecorder{}
	g, err := New(Config{Mode: KnockAuthOnly, Listen: "127.0.0.1:0", Auth: auth.ServerConfig{Secrets: auth.StaticSecrets{"client": secret}, Events: rec, ServerProof: true}, KnockMethod: knock.UDPMethod, KnockListen: "127.0.0.1:0", KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: secret}}, AllowTTL: 40 * time.Millisecond, Events: rec})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := g.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	if err := knock.SendUDP(context.Background(), knock.SendOptions{ServerAddr: g.knockAddr.String(), ClientID: "client", Secret: wrong, ServerPort: mustPort(t, ln.Addr()), SessionID: []byte("wrong-secret-session-1")}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	d := netx.Dialer{Config: auth.ClientConfig{ClientID: "client", Secret: secret, ServerPort: mustPort(t, ln.Addr()), AuthTimeout: 100 * time.Millisecond, RequireServerProof: true, SessionID: []byte("wrong-secret-session-1")}}
	if conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("auth succeeded after wrong-secret knock")
	}
	if err := knock.SendUDP(context.Background(), knock.SendOptions{ServerAddr: g.knockAddr.String(), ClientID: "client", Secret: secret, ServerPort: mustPort(t, ln.Addr()), SessionID: []byte("knock-session-01")}); err != nil {
		t.Fatal(err)
	}
	rec.waitKnocks(t, 1)
	d = netx.Dialer{Config: auth.ClientConfig{ClientID: "client", Secret: secret, ServerPort: mustPort(t, ln.Addr()), AuthTimeout: 100 * time.Millisecond, RequireServerProof: true, SessionID: []byte("different-session-1")}}
	if conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("auth succeeded with wrong session id")
	}
	if err := knock.SendUDP(context.Background(), knock.SendOptions{ServerAddr: g.knockAddr.String(), ClientID: "client", Secret: secret, ServerPort: mustPort(t, ln.Addr()), SessionID: []byte("expired-session-1")}); err != nil {
		t.Fatal(err)
	}
	rec.waitKnocks(t, 2)
	time.Sleep(80 * time.Millisecond)
	d = netx.Dialer{Config: auth.ClientConfig{ClientID: "client", Secret: secret, ServerPort: mustPort(t, ln.Addr()), AuthTimeout: 100 * time.Millisecond, RequireServerProof: true, SessionID: []byte("expired-session-1")}}
	if conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("auth succeeded after knock session expired")
	}
	select {
	case app := <-accepted:
		app.Close()
		t.Fatal("unexpected accepted application connection")
	default:
	}
}
