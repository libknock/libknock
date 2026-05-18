package knock

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/libknock/libknock/auth"
)

type synSeqState struct {
	firstSeen, lastSeen time.Time
	matched             int
	clientID            string
	slot                int64
}
type synSeqTracker struct {
	mu     sync.Mutex
	opts   SequenceOptions
	replay auth.ReplayCache
	states map[string]*synSeqState
	perIP  map[string]int
	total  int
}

func newSYNSequenceTracker(opts SequenceOptions, replay auth.ReplayCache) *synSeqTracker {
	opts = normalizedSequenceOptions(opts)
	if replay == nil {
		replay = newSYNReplayCache(time.Duration(opts.SlotSeconds) * time.Second * 3)
	}
	return &synSeqTracker{opts: opts, replay: replay, states: map[string]*synSeqState{}, perIP: map[string]int{}}
}

func (t *synSeqTracker) add(src net.IP, dstPort int, fields SYNFields, clients []ClientSecret, protectedPort int, now time.Time) (bool, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(now)
	ip := src.String()
	keyPrefix := ip + "\x00"
	for key, st := range t.states {
		if len(key) >= len(keyPrefix) && key[:len(keyPrefix)] == keyPrefix {
			if client, slot, ok := VerifySYNSeqPart(fields, dstPort, clients, protectedPort, now, t.opts.SlotSeconds, t.opts.Length, st.matched, t.opts.AllowLegacySYNSeq); ok && client == st.clientID && slot == st.slot {
				st.matched++
				st.lastSeen = now
				if st.matched >= t.opts.Length {
					delete(t.states, key)
					t.decInflightLocked(ip)
					return true, client
				}
				return false, ""
			}
		}
	}
	client, slot, ok := VerifySYNSeqPart(fields, dstPort, clients, protectedPort, now, t.opts.SlotSeconds, t.opts.Length, 0, t.opts.AllowLegacySYNSeq)
	if !ok || t.perIP[ip] >= t.opts.MaxInflightPerIP || t.total >= t.opts.MaxTotalInflight {
		return false, ""
	}
	if err := CheckSYNReplay(t.replay, client, fields, protectedPort); err != nil {
		return false, ""
	}
	if t.opts.Length == 1 {
		return true, client
	}
	key := fmt.Sprintf("%s\x00%s\x00%d", ip, client, slot)
	t.states[key] = &synSeqState{firstSeen: now, lastSeen: now, matched: 1, clientID: client, slot: slot}
	t.perIP[ip]++
	t.total++
	return false, ""
}

func (t *synSeqTracker) prune(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(now)
}

func (t *synSeqTracker) pruneLocked(now time.Time) {
	for key, st := range t.states {
		if now.Sub(st.firstSeen) > t.opts.Window {
			delete(t.states, key)
			if ip, _, ok := strings.Cut(key, "\x00"); ok {
				t.decInflightLocked(ip)
			} else if t.total > 0 {
				t.total--
			}
		}
	}
}

func (t *synSeqTracker) decInflightLocked(ip string) {
	if t.perIP[ip] > 0 {
		t.perIP[ip]--
		if t.perIP[ip] == 0 {
			delete(t.perIP, ip)
		}
	}
	if t.total > 0 {
		t.total--
	}
}
