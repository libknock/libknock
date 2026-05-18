package gate

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/firewall"
	"github.com/libknock/libknock/knock"
)

type recordingFirewall struct {
	mu      sync.Mutex
	revoked []netip.Addr
	config  firewall.Config
}

func (f *recordingFirewall) Name() string                                                { return "recording" }
func (f *recordingFirewall) Init(context.Context) error                                  { return nil }
func (f *recordingFirewall) Allow(context.Context, netip.Addr, int, time.Duration) error { return nil }
func (f *recordingFirewall) Revoke(_ context.Context, remote netip.Addr, _ int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, remote)
	return nil
}
func (f *recordingFirewall) Cleanup(context.Context) error { return nil }
func (f *recordingFirewall) Config() firewall.Config       { return f.config }
func (f *recordingFirewall) WithConfig(cfg firewall.Config) (firewall.Backend, error) {
	return &recordingFirewall{config: cfg}, nil
}
func (f *recordingFirewall) revokeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.revoked)
}

func TestFirewallOnlyTTLExpiresWildcardSessionAndRevokes(t *testing.T) {
	fw := &recordingFirewall{}
	g, err := New(Config{Mode: KnockFirewallOnly, Firewall: fw, KnockMethod: "udp", KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: testSecret()}}, AllowTTL: 25 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	remote := netip.MustParseAddr("192.0.2.10")
	g.store.Add(remote, firewallOnlyClientID, 25*time.Millisecond, 1)
	leaseID := g.store.MarkFirewall(remote, 443, 25*time.Millisecond)
	time.Sleep(35 * time.Millisecond)
	if !g.store.Expire(remote, firewallOnlyClientID, time.Now()) {
		t.Fatal("wildcard firewall-only session did not expire")
	}
	if !g.store.ExpireFirewall(remote, 443, leaseID, time.Now()) {
		t.Fatal("firewall lease did not expire")
	}
	if err := fw.Revoke(context.Background(), remote, 443); err != nil {
		t.Fatal(err)
	}
	if fw.revokeCount() != 1 {
		t.Fatalf("revoke count = %d, want 1", fw.revokeCount())
	}
}

func TestFirewallOnlyTTLRevokesAfterConsumedSession(t *testing.T) {
	fw := &recordingFirewall{}
	g, err := New(Config{Mode: KnockFirewallOnly, Firewall: fw, KnockMethod: "udp", KnockClients: []knock.ClientSecret{{ClientID: "client", Secret: testSecret()}}, AllowTTL: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	remote := netip.MustParseAddr("192.0.2.20")
	g.store.Add(remote, firewallOnlyClientID, 20*time.Millisecond, 1)
	leaseID := g.store.MarkFirewall(remote, 443, 20*time.Millisecond)
	if err := g.store.CheckAndConsume(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: firewallOnlyClientID}}, &net.TCPAddr{IP: remote.AsSlice(), Port: 50000}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if g.store.Expire(remote, firewallOnlyClientID, time.Now()) {
		t.Fatal("session lease unexpectedly remained after consumption")
	}
	if !g.store.ExpireFirewall(remote, 443, leaseID, time.Now()) {
		t.Fatal("firewall lease should expire independently after session consumption")
	}
	if err := fw.Revoke(context.Background(), remote, 443); err != nil {
		t.Fatal(err)
	}
	if fw.revokeCount() != 1 {
		t.Fatalf("revoke count = %d, want 1", fw.revokeCount())
	}
}
