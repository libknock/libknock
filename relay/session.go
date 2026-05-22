package relay

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/internal/cache"
	"github.com/libknock/libknock/internal/gatewaycore"
)

const DefaultMaxKnockSessions = 4096

// KnockSessionStore tracks short-lived knock admissions separately from firewall leases. It uses the internal TTL/LRU cache for bounded expiry, while preserving domain rules for session IDs, ports, and consumption counts.
type KnockSessionStore struct {
	mu       sync.Mutex
	sessions *cache.TTLLRU[sessionKey, *session]
	firewall *cache.TTLLRU[string, *firewallLease]
	nextID   uint64
}

type session struct {
	remaining int
	port      int
	sessionID []byte
}

type firewallLease struct {
	id uint64
}

func NewKnockSessionStore() *KnockSessionStore {
	return NewKnockSessionStoreWithLimit(DefaultMaxKnockSessions)
}
func NewKnockSessionStoreWithLimit(max int) *KnockSessionStore {
	if max <= 0 {
		max = DefaultMaxKnockSessions
	}
	return &KnockSessionStore{sessions: cache.NewTTLLRU[sessionKey, *session](max), firewall: cache.NewTTLLRU[string, *firewallLease](max)}
}
func (s *KnockSessionStore) Add(remote netip.Addr, clientID string, ttl time.Duration, uses int) {
	s.AddSession(remote, clientID, nil, ttl, uses)
}

func (s *KnockSessionStore) AddSession(remote netip.Addr, clientID string, sessionID []byte, ttl time.Duration, uses int) {
	s.AddSessionForPort(remote, clientID, sessionID, 0, ttl, uses)
}

func (s *KnockSessionStore) AddSessionForPort(remote netip.Addr, clientID string, sessionID []byte, port int, ttl time.Duration, uses int) {
	if s == nil || !remote.IsValid() || clientID == "" {
		return
	}
	if uses <= 0 {
		uses = 1
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions.SetUntil(newSessionKeyForPort(remote, clientID, port), &session{remaining: uses, port: port, sessionID: append([]byte(nil), sessionID...)}, now.Add(ttl))
}
func (s *KnockSessionStore) CheckAndConsume(peer auth.PeerInfo, remote net.Addr) error {
	if s == nil {
		return errors.New("missing knock session store")
	}
	addr, ok := gatewaycore.AddrFromNet(remote)
	if !ok {
		return errors.New("remote address has no IP")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	key := newSessionKeyForPort(addr, peer.ClientID, peer.ServerPort)
	sess, ok, expired := s.getSessionLocked(key, now)
	if !ok && !expired && peer.ServerPort == 0 {
		key = newSessionKey(addr, peer.ClientID)
		sess, ok, expired = s.getSessionLocked(key, now)
	}
	if expired {
		return errors.New("knock session expired")
	}
	if !ok {
		return errors.New("no accepted knock session")
	}
	if len(sess.sessionID) > 0 && !bytes.Equal(sess.sessionID, peer.SessionID) {
		return errors.New("knock session id mismatch")
	}
	if sess.port > 0 && peer.ServerPort > 0 && sess.port != peer.ServerPort {
		return errors.New("knock session port mismatch")
	}
	sess.remaining--
	if sess.remaining <= 0 {
		s.sessions.Delete(key)
	}
	return nil
}

// getSessionLocked is called with KnockSessionStore.mu held. The lock order is
// fixed as KnockSessionStore.mu -> TTLLRU.mu; never call back into the session
// store while holding a TTLLRU lock.
func (s *KnockSessionStore) getSessionLocked(key sessionKey, now time.Time) (*session, bool, bool) {
	entry, ok := s.sessions.Peek(key)
	if !ok {
		return nil, false, false
	}
	if !entry.ExpiresAt.After(now) {
		s.sessions.Delete(key)
		return nil, false, true
	}
	return entry.Value, true, false
}

func (s *KnockSessionStore) Remove(remote netip.Addr, clientID string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removeSessionsLocked(remote, clientID) > 0
}
func (s *KnockSessionStore) RemoveForPort(remote netip.Addr, clientID string, port int) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions.Delete(newSessionKeyForPort(remote, clientID, port))
}
func (s *KnockSessionStore) Expire(remote netip.Addr, clientID string, now time.Time) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions.DeleteWhere(func(entry cache.Entry[sessionKey, *session]) bool {
		return sessionKeyMatches(entry.Key, remote, clientID) && !now.Before(entry.ExpiresAt)
	}) > 0
}
func (s *KnockSessionStore) ExpireForPort(remote netip.Addr, clientID string, port int, now time.Time) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions.DeleteWhere(func(entry cache.Entry[sessionKey, *session]) bool {
		return newSessionKeyForPort(remote, clientID, port) == entry.Key && !now.Before(entry.ExpiresAt)
	}) > 0
}
func (s *KnockSessionStore) removeSessionsLocked(remote netip.Addr, clientID string) int {
	return s.sessions.DeleteWhere(func(entry cache.Entry[sessionKey, *session]) bool {
		return sessionKeyMatches(entry.Key, remote, clientID)
	})
}
func (s *KnockSessionStore) MarkFirewall(remote netip.Addr, port int, ttl time.Duration) (uint64, bool) {
	if s == nil || !remote.IsValid() || port <= 0 || ttl <= 0 {
		return 0, false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.firewall.Sweep(now)
	key := firewallKey(remote, port)
	if entry, ok := s.firewall.Peek(key); ok && entry.ExpiresAt.After(now) {
		s.nextID++
		id := s.nextID
		s.firewall.SetUntil(key, &firewallLease{id: id}, now.Add(ttl))
		return id, true
	}
	if s.firewall.ActiveLen(now) >= s.firewall.Cap() {
		return 0, false
	}
	s.nextID++
	id := s.nextID
	s.firewall.SetUntil(key, &firewallLease{id: id}, now.Add(ttl))
	return id, true
}
func (s *KnockSessionStore) ExpireFirewall(remote netip.Addr, port int, id uint64, now time.Time) bool {
	if s == nil || id == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := firewallKey(remote, port)
	lease, ok := s.firewall.Peek(key)
	if !ok || lease.Value.id != id || now.Before(lease.ExpiresAt) {
		return false
	}
	return s.firewall.Delete(key)
}
func (s *KnockSessionStore) RemoveFirewall(remote netip.Addr, port int) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.firewall.Delete(firewallKey(remote, port))
}

type sessionKey struct {
	Remote   netip.Addr
	ClientID string
	Port     uint16
}

func newSessionKey(addr netip.Addr, clientID string) sessionKey {
	return newSessionKeyForPort(addr, clientID, 0)
}
func newSessionKeyForPort(addr netip.Addr, clientID string, port int) sessionKey {
	if port < 0 || port > 65535 {
		port = 0
	}
	return sessionKey{Remote: addr, ClientID: clientID, Port: uint16(port)}
}
func sessionKeyMatches(key sessionKey, addr netip.Addr, clientID string) bool {
	return key.Remote == addr && key.ClientID == clientID
}
func firewallKey(addr netip.Addr, port int) string {
	return fmt.Sprintf("%s\x00%d", addr.String(), port)
}
