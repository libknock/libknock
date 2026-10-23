// Package iplimit provides source-address keys and a per-source concurrency
// limiter used to keep a single client (or a single IPv6 /64) from occupying
// every pending/auth slot.
package iplimit

import (
	"net"
	"net/netip"
	"sync"
)

// IPv6PrefixBits is the prefix length IPv6 sources are aggregated to. A single
// end site is usually delegated at least a /64, so per-/128 accounting lets one
// attacker mint effectively unlimited keys.
const IPv6PrefixBits = 64

// Key returns a stable per-source key for addr. IPv4 (including IPv4-mapped
// IPv6) addresses map to the bare address; IPv6 addresses map to their /64
// prefix. ok is false when addr carries no parseable IP.
func Key(addr net.Addr) (key string, ok bool) {
	ip, ok := addrIP(addr)
	if !ok {
		return "", false
	}
	return KeyFromAddr(ip), true
}

// KeyFromAddr returns the per-source key for an already-parsed address.
func KeyFromAddr(ip netip.Addr) string {
	ip = ip.Unmap().WithZone("")
	if ip.Is4() {
		return ip.String()
	}
	prefix, err := ip.Prefix(IPv6PrefixBits)
	if err != nil {
		return ip.String()
	}
	return prefix.String()
}

func addrIP(addr net.Addr) (netip.Addr, bool) {
	switch a := addr.(type) {
	case nil:
		return netip.Addr{}, false
	case *net.TCPAddr:
		if a == nil {
			return netip.Addr{}, false
		}
		ip, ok := netip.AddrFromSlice(a.IP)
		return ip, ok
	case *net.UDPAddr:
		if a == nil {
			return netip.Addr{}, false
		}
		ip, ok := netip.AddrFromSlice(a.IP)
		return ip, ok
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip, true
}

// Limiter caps the number of concurrently held slots per source key. A nil
// Limiter or one with max <= 0 never limits.
type Limiter struct {
	max int
	mu  sync.Mutex
	n   map[string]int
}

// New returns a Limiter allowing at most max concurrent slots per source. A
// max <= 0 disables limiting and New returns nil.
func New(max int) *Limiter {
	if max <= 0 {
		return nil
	}
	return &Limiter{max: max, n: make(map[string]int)}
}

// Acquire reserves a slot for addr. It returns a release function and true on
// success. Addresses without a parseable IP are not limited. The release
// function is safe to call more than once.
func (l *Limiter) Acquire(addr net.Addr) (release func(), ok bool) {
	if l == nil {
		return func() {}, true
	}
	key, ok := Key(addr)
	if !ok {
		return func() {}, true
	}
	l.mu.Lock()
	if l.n[key] >= l.max {
		l.mu.Unlock()
		return nil, false
	}
	l.n[key]++
	l.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			if l.n[key] <= 1 {
				delete(l.n, key)
			} else {
				l.n[key]--
			}
			l.mu.Unlock()
		})
	}, true
}
