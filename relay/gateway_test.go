package relay

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/firewall"
	"github.com/libknock/libknock/internal/gatewaycore"
	"github.com/libknock/libknock/internal/timerset"
	"github.com/libknock/libknock/knock"
	"github.com/libknock/libknock/netx"
)

func TestGatewayRelaysAuthenticatedTCP(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	gatewayLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := gatewayLn.Addr().String()
	_ = gatewayLn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Gateway{
			Listen:                 listen,
			Upstream:               upstream.Addr().String(),
			Auth:                   auth.ServerConfig{ServerPort: mustPort(t, listen), Secrets: auth.StaticSecrets{"client-001": secret}},
			UpstreamConnectTimeout: time.Second,
			IdleTimeout:            time.Second,
		}.Run(ctx)
	}()
	waitTCP(t, listen)
	d := netx.Dialer{Config: auth.ClientConfig{ClientID: "client-001", Secret: secret, ServerPort: mustPort(t, listen), AuthTimeout: time.Second}}
	conn, err := d.DialContext(context.Background(), "tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not stop")
	}
}

func waitTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", addr)
}

func mustPort(t *testing.T, addr string) int {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var p int
	if _, err := fmt.Sscanf(port, "%d", &p); err != nil {
		t.Fatal(err)
	}
	return p
}

type gatewayRecordingFirewall struct {
	mu           sync.Mutex
	revoked      []netip.Addr
	revokedPorts []int
	revokeCtxErr chan error
}

func (f *gatewayRecordingFirewall) Name() string               { return "recording" }
func (f *gatewayRecordingFirewall) Init(context.Context) error { return nil }
func (f *gatewayRecordingFirewall) Allow(context.Context, netip.Addr, int, time.Duration) error {
	return nil
}
func (f *gatewayRecordingFirewall) Revoke(ctx context.Context, remote netip.Addr, port int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, remote)
	f.revokedPorts = append(f.revokedPorts, port)
	if f.revokeCtxErr != nil {
		f.revokeCtxErr <- ctx.Err()
	}
	return nil
}
func (f *gatewayRecordingFirewall) Cleanup(context.Context) error { return nil }
func (f *gatewayRecordingFirewall) revokeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.revoked)
}
func (f *gatewayRecordingFirewall) lastRevokePort() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.revokedPorts) == 0 {
		return 0
	}
	return f.revokedPorts[len(f.revokedPorts)-1]
}

func TestGatewayRemoveAfterAuthRevokesFirewall(t *testing.T) {
	fw := &gatewayRecordingFirewall{}
	store := NewKnockSessionStore()
	remote := netip.MustParseAddr("127.0.0.1")
	store.AddSessionForPort(remote, "client", nil, 9443, time.Minute, 1)
	g := Gateway{Listen: "127.0.0.1:9443", RemoveAfterAuth: true}
	g.removeKnockAccess(&net.TCPAddr{IP: remote.AsSlice(), Port: 50000}, "client", 9443, fw, store)
	if fw.revokeCount() != 1 {
		t.Fatalf("revoke count = %d, want 1", fw.revokeCount())
	}
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}}, &net.TCPAddr{IP: remote.AsSlice(), Port: 50001}); err == nil {
		t.Fatal("knock session remained after RemoveAfterAuth")
	}
}

func TestGatewayTTLFirewallLeaseSurvivesConsumedSession(t *testing.T) {
	fw := &gatewayRecordingFirewall{}
	store := NewKnockSessionStore()
	remote := netip.MustParseAddr("127.0.0.1")
	store.Add(remote, "client", 20*time.Millisecond, 1)
	leaseID, ok := store.MarkFirewall(remote, 9443, 20*time.Millisecond)
	if !ok {
		t.Fatal("mark firewall lease failed")
	}
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}}, &net.TCPAddr{IP: remote.AsSlice(), Port: 50000}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if store.Expire(remote, "client", time.Now()) {
		t.Fatal("session lease unexpectedly remained after consumption")
	}
	if !store.ExpireFirewall(remote, 9443, leaseID, time.Now()) {
		t.Fatal("firewall lease should expire independently after session consumption")
	}
	if err := fw.Revoke(context.Background(), remote, 9443); err != nil {
		t.Fatal(err)
	}
	if fw.revokeCount() != 1 {
		t.Fatalf("revoke count = %d, want 1", fw.revokeCount())
	}
}

func TestGatewayAuthConcurrencyLimitRejectsOverflow(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	gatewayLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := gatewayLn.Addr().String()
	_ = gatewayLn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Gateway{
			Listen:         listen,
			Upstream:       "127.0.0.1:1",
			Auth:           auth.ServerConfig{ServerPort: mustPort(t, listen), Secrets: auth.StaticSecrets{"client-001": secret}, AuthTimeout: 250 * time.Millisecond},
			MaxPendingAuth: 1,
			MaxAuthWorkers: 1,
		}.Run(ctx)
	}()
	waitTCP(t, listen)
	blocker, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	var overflow []net.Conn
	defer func() {
		for _, conn := range overflow {
			_ = conn.Close()
		}
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", listen, 50*time.Millisecond)
		if err != nil {
			continue
		}
		overflow = append(overflow, conn)
		_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		buf := []byte{0}
		if _, err := conn.Read(buf); err != nil {
			cancel()
			select {
			case err := <-errCh:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("gateway did not stop")
			}
			return
		}
	}
	t.Fatal("overflow connection was not rejected")
}

func TestGatewayRemoveAfterAuthFallsBackToConnLocalPort(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	store := NewKnockSessionStore()
	fw := &gatewayRecordingFirewall{}
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		conn, err := upstream.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := gatewaycore.ListenerPort(ln.Addr())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := Gateway{Upstream: upstream.Addr().String(), Auth: auth.ServerConfig{ServerPort: port, Secrets: auth.StaticSecrets{"client": secret}, ReplayCache: auth.NewMemoryReplayCache(time.Minute), KnockStore: store}, RemoveAfterAuth: true}
	addr := netip.MustParseAddr("127.0.0.1")
	store.Add(addr, "client", time.Minute, 1)
	_, _ = store.MarkFirewall(addr, port, time.Minute)
	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			g.handleConn(ctx, conn, g.Auth, fw, store)
		}
		close(done)
	}()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ClientAuth(ctx, conn, auth.ClientConfig{ClientID: "client", Secret: secret, ServerPort: port}); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handleConn did not finish")
	}
	if got := fw.lastRevokePort(); got != port {
		t.Fatalf("revoke port = %d, want %d", got, port)
	}
	if store.RemoveFirewall(addr, port) {
		t.Fatal("firewall lease was not removed")
	}
}

func TestGatewayListenKnockUsesDerivedProtectedPort(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	store := NewKnockSessionStore()
	fw := &gatewayRecordingFirewall{}
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := ln.LocalAddr().String()
	_ = ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := Gateway{Listen: "127.0.0.1:0", KnockMethod: "udp", KnockListen: listen, KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: secret}}, AllowTTL: time.Minute}
	errCh := make(chan error, 1)
	timers := timerset.New()
	defer timers.StopAll()
	go func() { errCh <- g.listenKnock(ctx, fw, store, 9443, timers) }()
	deadline := time.Now().Add(2 * time.Second)
	remote := netip.MustParseAddr("127.0.0.1")
	var lastSendErr error
	sessionID := []byte("gateway-session1")
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatal(err)
		default:
		}
		lastSendErr = knock.SendMethod(ctx, knock.UDPMethod, knock.SendOptions{ServerAddr: listen, ClientID: "client", Secret: secret, ServerPort: 9443, SessionID: sessionID})
		for range 5 {
			if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}, ServerPort: 9443, SessionID: sessionID}, &net.TCPAddr{IP: remote.AsSlice(), Port: 50000}); err == nil {
				return
			}
			select {
			case err := <-errCh:
				t.Fatal(err)
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	if lastSendErr != nil {
		t.Fatalf("send knock: %v", lastSendErr)
	}
	t.Fatal("knock listener did not accept frame for derived protected port")
}

func TestGatewayListenKnockTimerRevokeUsesDetachedContext(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	store := NewKnockSessionStore()
	fw := &gatewayRecordingFirewall{revokeCtxErr: make(chan error, 1)}
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := ln.LocalAddr().String()
	_ = ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := Gateway{Listen: "127.0.0.1:0", KnockMethod: "udp", KnockListen: listen, KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: secret}}, AllowTTL: 80 * time.Millisecond}
	errCh := make(chan error, 1)
	timers := timerset.New()
	defer timers.StopAll()
	go func() { errCh <- g.listenKnock(ctx, fw, store, 9443, timers) }()
	remote := netip.MustParseAddr("127.0.0.1")
	sessionID := []byte("gateway-session2")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("knock listener exited early: %v", err)
		default:
		}
		if err := knock.SendMethod(ctx, knock.UDPMethod, knock.SendOptions{ServerAddr: listen, ClientID: "client", Secret: secret, ServerPort: 9443, SessionID: sessionID}); err != nil {
			t.Fatal(err)
		}
		if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}, ServerPort: 9443, SessionID: sessionID}, &net.TCPAddr{IP: remote.AsSlice(), Port: 50000}); err == nil {
			cancel()
			select {
			case err := <-fw.revokeCtxErr:
				if err != nil {
					t.Fatalf("revoke ctx err = %v, want nil", err)
				}
			case <-time.After(time.Second):
				t.Fatal("timer revoke was not called")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("knock listener did not accept frame")
}

type gatewayEventRecorder struct {
	mu     sync.Mutex
	errors []RelayErrorEvent
}

func (r *gatewayEventRecorder) OnKnockOK(KnockEvent)               {}
func (r *gatewayEventRecorder) OnKnockFail(KnockFailEvent)         {}
func (r *gatewayEventRecorder) OnFirewallAllow(FirewallEvent)      {}
func (r *gatewayEventRecorder) OnFirewallError(FirewallErrorEvent) {}
func (r *gatewayEventRecorder) OnRelayOK(RelayEvent)               {}
func (r *gatewayEventRecorder) OnRelayError(ev RelayErrorEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errors = append(r.errors, ev)
}
func (r *gatewayEventRecorder) hasRelayError(stage string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ev := range r.errors {
		if ev.Stage == stage && ev.Err != nil {
			return true
		}
	}
	return false
}

func TestGatewayRunStopsWhenKnockListenerFails(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	holdUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer holdUDP.Close()
	gatewayLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := gatewayLn.Addr().String()
	_ = gatewayLn.Close()
	rec := &gatewayEventRecorder{}
	errCh := make(chan error, 1)
	go func() {
		errCh <- Gateway{
			Listen:       listen,
			Upstream:     "127.0.0.1:1",
			Auth:         auth.ServerConfig{ServerPort: mustPort(t, listen), Secrets: auth.StaticSecrets{"client": secret}},
			KnockMethod:  "udp",
			KnockListen:  holdUDP.LocalAddr().String(),
			KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: secret}},
			Events:       rec,
		}.Run(context.Background())
	}()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected knock listener error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not stop after knock listener failure")
	}
	if !rec.hasRelayError("knock") {
		t.Fatal("expected knock listener failure to be recorded as relay error")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", listen, 50*time.Millisecond)
		if err != nil {
			return
		}
		_ = conn.Close()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("tcp listener still accepted connections after knock listener failure")
}

func TestGatewayRejectsDropUDPForActiveUDP(t *testing.T) {
	err := Gateway{Listen: "127.0.0.1:0", Upstream: "127.0.0.1:1", Firewall: firewall.NewIptables(firewall.Config{Port: 9443, DropUDPKnockPort: true}), KnockMethod: knock.UDPMethod}.Run(context.Background())
	if err == nil {
		t.Fatal("expected drop_udp_knock_port to be rejected for active udp")
	}
}

func TestGatewayAllowsDropUDPForUDPPassive(t *testing.T) {
	fw := firewall.NewIptables(firewall.Config{Port: 9443, DropUDPKnockPort: true})
	if err := gatewaycore.ValidateDropUDPKnockPort(fw, knock.UDPPassiveMethod); err != nil {
		t.Fatal(err)
	}
}

func TestGatewaySkipsManualRevokeForTimeoutBackends(t *testing.T) {
	if gatewaycore.ShouldManualRevoke(&timeoutNamedFirewall{name: "ipset-iptables"}) {
		t.Fatal("ipset-iptables should use kernel timeout instead of manual revoke")
	}
	if !gatewaycore.ShouldManualRevoke(&timeoutNamedFirewall{name: "iptables"}) {
		t.Fatal("iptables should require manual revoke")
	}
}

type timeoutNamedFirewall struct {
	gatewayRecordingFirewall
	name string
}

func (f *timeoutNamedFirewall) Name() string { return f.name }

func TestGatewayRejectsFirewallWithoutKnockMethod(t *testing.T) {
	err := Gateway{Listen: "127.0.0.1:0", Upstream: "127.0.0.1:1", Firewall: firewall.NewIptables(firewall.Config{Port: 9443})}.Run(context.Background())
	if err == nil {
		t.Fatal("expected firewall without knock method to be rejected")
	}
}

func TestKnockSessionStoreEvictsOldestAtLimit(t *testing.T) {
	store := NewKnockSessionStoreWithLimit(1)
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("192.0.2.2")
	store.Add(first, "client", time.Minute, 1)
	store.Add(second, "client", time.Minute, 1)
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}}, &net.TCPAddr{IP: first.AsSlice(), Port: 1234}); err == nil {
		t.Fatal("oldest session was not evicted")
	}
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}}, &net.TCPAddr{IP: second.AsSlice(), Port: 1234}); err != nil {
		t.Fatalf("newest session missing: %v", err)
	}
}

func TestKnockSessionStoreRejectsFirewallLeaseAtLimit(t *testing.T) {
	store := NewKnockSessionStoreWithLimit(1)
	first := netip.MustParseAddr("192.0.2.11")
	second := netip.MustParseAddr("192.0.2.12")
	firstID, ok := store.MarkFirewall(first, 443, time.Minute)
	if !ok {
		t.Fatal("mark first firewall lease failed")
	}
	if secondID, ok := store.MarkFirewall(second, 443, time.Minute); ok || secondID != 0 {
		t.Fatalf("second firewall lease ok=%v id=%d, want rejection", ok, secondID)
	}
	if !store.ExpireFirewall(first, 443, firstID, time.Now().Add(time.Hour)) {
		t.Fatal("active firewall lease was silently evicted")
	}
}

func TestGatewayUDPListenForKnockPortUsesConfiguredPort(t *testing.T) {
	if got := gatewaycore.UDPListenStringForKnockPort("127.0.0.1:9000", 10000); got != "127.0.0.1:10000" {
		t.Fatalf("udp listen = %q, want 127.0.0.1:10000", got)
	}
	if got := gatewaycore.UDPListenStringForKnockPort("127.0.0.1:9000", 0); got != "127.0.0.1:9000" {
		t.Fatalf("udp listen fallback = %q, want 127.0.0.1:9000", got)
	}
}

func TestListenerPortRejectsMalformedPort(t *testing.T) {
	if got := gatewaycore.ListenerPort(mockAddr("127.0.0.1:http")); got != 0 {
		t.Fatalf("listenerPort malformed = %d, want 0", got)
	}
}

type mockAddr string

func (m mockAddr) Network() string { return "tcp" }
func (m mockAddr) String() string  { return string(m) }

func TestGatewayRejectsRemoveAfterAuthWithMultipleConnectionsPerKnock(t *testing.T) {
	g := Gateway{Listen: "127.0.0.1:0", Upstream: "127.0.0.1:1", RemoveAfterAuth: true, MaxConnectionsPerKnock: 2}
	if err := g.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "remove_after_auth=true conflicts") {
		t.Fatalf("Run err = %v, want remove_after_auth conflict", err)
	}
}

func TestKnockSessionStoreRequiresMatchingSessionID(t *testing.T) {
	store := NewKnockSessionStore()
	remote := netip.MustParseAddr("192.0.2.30")
	store.AddSessionForPort(remote, "client", []byte("session-a"), 9443, time.Minute, 1)
	remoteAddr := &net.TCPAddr{IP: remote.AsSlice(), Port: 50000}
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}, ServerPort: 9443, SessionID: []byte("session-b")}, remoteAddr); err == nil || !strings.Contains(err.Error(), "session id mismatch") {
		t.Fatalf("mismatched session err = %v", err)
	}
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}, ServerPort: 9443, SessionID: []byte("session-a")}, remoteAddr); err != nil {
		t.Fatalf("matching session err = %v", err)
	}
}

func TestKnockSessionStoreBindsServerPort(t *testing.T) {
	store := NewKnockSessionStore()
	remote := netip.MustParseAddr("192.0.2.31")
	store.AddSessionForPort(remote, "client", []byte("session-a"), 9443, time.Minute, 1)
	remoteAddr := &net.TCPAddr{IP: remote.AsSlice(), Port: 50000}
	err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}, ServerPort: 9444, SessionID: []byte("session-a")}, remoteAddr)
	if err == nil || !strings.Contains(err.Error(), "no accepted knock session") {
		t.Fatalf("wrong port err = %v", err)
	}
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}, ServerPort: 9443, SessionID: []byte("session-a")}, remoteAddr); err != nil {
		t.Fatalf("matching port err = %v", err)
	}
}

func TestRemoveAfterAuthRemovesOnlyMatchingPortSession(t *testing.T) {
	store := NewKnockSessionStore()
	fw := &gatewayRecordingFirewall{}
	remote := netip.MustParseAddr("127.0.0.1")
	store.AddSessionForPort(remote, "client", []byte("session-a"), 9443, time.Minute, 1)
	store.AddSessionForPort(remote, "client", []byte("session-b"), 9444, time.Minute, 1)
	g := Gateway{Listen: "127.0.0.1:9443", RemoveAfterAuth: true}
	g.removeKnockAccess(&net.TCPAddr{IP: remote.AsSlice(), Port: 50000}, "client", 9443, fw, store)
	remoteAddr := &net.TCPAddr{IP: remote.AsSlice(), Port: 50001}
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}, ServerPort: 9443, SessionID: []byte("session-a")}, remoteAddr); err == nil {
		t.Fatal("matching port session remained after RemoveAfterAuth")
	}
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}, ServerPort: 9444, SessionID: []byte("session-b")}, remoteAddr); err != nil {
		t.Fatalf("other port session was removed: %v", err)
	}
}

func TestGatewayRejectsUnsupportedKnockMethodBeforeListen(t *testing.T) {
	err := Gateway{Listen: "127.0.0.1:0", Upstream: "127.0.0.1:1", Firewall: firewall.Noop{}, KnockMethod: "not-a-method", KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: []byte("0123456789abcdef0123456789abcdef")}}}.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), `unsupported knock method "not-a-method"`) {
		t.Fatalf("Run err = %v", err)
	}
}

func TestKnockSessionStoreSeparatesStructuredSessionKeyFields(t *testing.T) {
	store := NewKnockSessionStore()
	remoteA := netip.MustParseAddr("192.0.2.41")
	remoteB := netip.MustParseAddr("192.0.2.42")
	store.AddSessionForPort(remoteA, "client", []byte("port-a"), 9443, time.Minute, 1)
	store.AddSessionForPort(remoteA, "client", []byte("port-b"), 9444, time.Minute, 1)
	store.AddSessionForPort(remoteA, "other", []byte("client-b"), 9443, time.Minute, 1)
	store.AddSessionForPort(remoteB, "client", []byte("remote-b"), 9443, time.Minute, 1)
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}, ServerPort: 9443, SessionID: []byte("port-b")}, &net.TCPAddr{IP: remoteA.AsSlice(), Port: 50000}); err == nil {
		t.Fatal("same client/ip with different port reused the wrong session")
	}
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "other"}, ServerPort: 9443, SessionID: []byte("port-a")}, &net.TCPAddr{IP: remoteA.AsSlice(), Port: 50000}); err == nil {
		t.Fatal("same ip/port with different client reused the wrong session")
	}
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}, ServerPort: 9443, SessionID: []byte("remote-b")}, &net.TCPAddr{IP: remoteA.AsSlice(), Port: 50000}); err == nil {
		t.Fatal("same client/port with different remote reused the wrong session")
	}
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}, ServerPort: 9444, SessionID: []byte("port-b")}, &net.TCPAddr{IP: remoteA.AsSlice(), Port: 50000}); err != nil {
		t.Fatalf("matching port-specific session err = %v", err)
	}
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "other"}, ServerPort: 9443, SessionID: []byte("client-b")}, &net.TCPAddr{IP: remoteA.AsSlice(), Port: 50001}); err != nil {
		t.Fatalf("matching client-specific session err = %v", err)
	}
	if err := store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client"}, ServerPort: 9443, SessionID: []byte("remote-b")}, &net.TCPAddr{IP: remoteB.AsSlice(), Port: 50002}); err != nil {
		t.Fatalf("matching remote-specific session err = %v", err)
	}
}
