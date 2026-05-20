package knock

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/internal/cache"
)

type seqState struct {
	firstSeen time.Time
	lastSeen  time.Time
	parts     []bool
	sessionID []byte
	total     int
}

type sequenceTracker struct {
	mu        sync.Mutex
	opts      SequenceOptions
	states    map[string]*seqState
	perIP     map[string]int
	total     int
	completed *cache.TTLLRU[string, struct{}]
	nonceTT   time.Duration
}

func newSequenceTracker(opts SequenceOptions, nonceTTL time.Duration) *sequenceTracker {
	opts = normalizedSequenceOptions(opts)
	if nonceTTL <= opts.Window {
		nonceTTL = 2 * time.Minute
	}
	return &sequenceTracker{opts: opts, states: map[string]*seqState{}, perIP: map[string]int{}, completed: cache.NewTTLLRU[string, struct{}](opts.MaxTotalInflight), nonceTT: nonceTTL}
}

func SendUDPSequence(ctx context.Context, opts SendOptions) error {
	return SendUDPSequenceMethod(ctx, opts, UDPSeqMethod)
}

func SendUDPSequenceMethod(ctx context.Context, opts SendOptions, method string) error {
	ctx = backgroundIfNil(ctx)
	if method == "" {
		method = UDPSeqMethod
	}
	if err := ValidateSendOptions(opts); err != nil {
		return err
	}
	seq := normalizedSequenceOptions(opts.Sequence)
	if seq.Length < 2 || seq.Length > DefaultSequenceMaxParts {
		return fmt.Errorf("udp sequence length must be between 2 and %d", DefaultSequenceMaxParts)
	}
	sequenceID := make([]byte, KnockSequenceIDBytes)
	if _, err := rand.Read(sequenceID); err != nil {
		return err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", opts.ServerAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	}
	for i := 0; i < seq.Length; i++ {
		data, err := BuildKnockFrame(KnockFrameOptions{
			ClientID:      opts.ClientID,
			Secret:        opts.Secret,
			ServerPort:    opts.ServerPort,
			Method:        method,
			SessionID:     opts.SessionID,
			SequenceID:    sequenceID,
			SequenceIndex: i,
			SequenceTotal: seq.Length,
			MaxFrameSize:  opts.MaxFrameSize,
		})
		if err != nil {
			return err
		}
		if _, err := conn.Write(data); err != nil {
			return err
		}
		if err := sleepSequenceInterval(ctx, i, seq.Length, seq); err != nil {
			return err
		}
	}
	return nil
}

type udpSequenceListener struct {
	conn net.PacketConn
	opts ListenOptions
}

func NewUDPSequenceListener(listen string, opts ListenOptions) (KnockListener, error) {
	if listen == "" {
		return nil, fmt.Errorf("udp listen address is required")
	}
	if err := ValidateClientSecrets(opts.Clients); err != nil {
		return nil, err
	}
	conn, err := net.ListenPacket("udp", listen)
	if err != nil {
		return nil, err
	}
	return &udpSequenceListener{conn: conn, opts: opts}, nil
}

func (l *udpSequenceListener) Close() error   { return l.conn.Close() }
func (l *udpSequenceListener) Addr() net.Addr { return l.conn.LocalAddr() }

func (l *udpSequenceListener) Serve(ctx context.Context, handler Handler) error {
	ctx = backgroundIfNil(ctx)
	defer l.Close()
	go func() { <-ctx.Done(); _ = l.Close() }()
	opts := l.opts
	tracker := newSequenceTracker(opts.Sequence, opts.NonceTTL)
	replay := replayCache(opts)
	maxFrameSize := maxKnockFrameSize(opts)
	buf := make([]byte, maxFrameSize)
	for {
		n, addr, err := l.conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok || udpAddr.IP == nil {
			continue
		}
		if !allowKnockPacket(opts, udpAddr.IP) {
			continue
		}
		info, err := OpenKnockFrame(buf[:n], ServerConfig{Clients: opts.Clients, ServerPort: opts.Port, Method: UDPSeqMethod, TimeWindow: opts.TimeWindow, MaxFrameSize: maxFrameSize, ReplayCache: replay, AllowSequence: true})
		if err != nil {
			if opts.InvalidPacket != nil {
				opts.InvalidPacket(udpAddr.IP, err.Error())
			}
			continue
		}
		if err := requireKnockSessionID(opts, info); err != nil {
			if opts.InvalidPacket != nil {
				opts.InvalidPacket(udpAddr.IP, err.Error())
			}
			continue
		}
		complete, err := tracker.add(udpAddr.IP, info, time.Now())
		if err != nil {
			if opts.InvalidPacket != nil {
				opts.InvalidPacket(udpAddr.IP, err.Error())
			}
			continue
		}
		if complete {
			handler(Event{SourceIP: udpAddr.IP, ClientID: info.ClientID, Nonce: hex.EncodeToString(info.Nonce), Parts: info.SequenceTotal, Method: UDPSeqMethod, SessionID: info.SessionID})
		}
	}
}

func ListenUDPSequence(ctx context.Context, listen string, opts ListenOptions, handler Handler) error {
	listener, err := NewUDPSequenceListener(listen, opts)
	if err != nil {
		return err
	}
	return listener.Serve(ctx, handler)
}

func (t *sequenceTracker) add(src net.IP, info *KnockInfo, now time.Time) (bool, error) {
	if info == nil || info.FrameType != KnockFrameTypeUDPSequence {
		return false, auth.ErrInvalidFrame
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(now)
	if info.SequenceTotal != t.opts.Length || info.SequenceTotal < 2 || info.SequenceTotal > DefaultSequenceMaxParts || info.SequenceIndex < 0 || info.SequenceIndex >= info.SequenceTotal {
		return false, fmt.Errorf("invalid udp sequence index or total")
	}
	key := sequenceStateKey(src, info)
	if _, ok := t.completed.GetAt(key, now); ok {
		return false, auth.ErrReplayDetected
	}
	state := t.states[key]
	if state == nil {
		if t.perIP[src.String()] >= t.opts.MaxInflightPerIP {
			return false, fmt.Errorf("sequence_inflight_per_ip_exceeded")
		}
		if t.total >= t.opts.MaxTotalInflight {
			return false, fmt.Errorf("sequence_inflight_total_exceeded")
		}
		state = &seqState{firstSeen: now, parts: make([]bool, info.SequenceTotal), sessionID: append([]byte(nil), info.SessionID...), total: info.SequenceTotal}
		t.states[key] = state
		t.perIP[src.String()]++
		t.total++
	}
	if now.Sub(state.firstSeen) > t.opts.Window {
		t.removeLocked(key, src.String())
		return false, fmt.Errorf("sequence_timeout")
	}
	if state.total != info.SequenceTotal || !bytes.Equal(state.sessionID, info.SessionID) {
		return false, auth.ErrAuthFailed
	}
	if state.parts[info.SequenceIndex] {
		return false, fmt.Errorf("duplicate_part")
	}
	state.parts[info.SequenceIndex] = true
	state.lastSeen = now
	for _, seen := range state.parts {
		if !seen {
			return false, nil
		}
	}
	t.markCompletedLocked(key, now)
	t.removeLocked(key, src.String())
	return true, nil
}

func sequenceStateKey(src net.IP, info *KnockInfo) string {
	return src.String() + "\x00" + info.ClientID + "\x00" + hex.EncodeToString(info.SequenceID) + "\x00" + fmt.Sprint(info.ServerPort) + "\x00" + info.Method
}

func (t *sequenceTracker) pruneLocked(now time.Time) {
	for key, state := range t.states {
		if now.Sub(state.firstSeen) > t.opts.Window {
			parts := splitStateKey(key)
			if len(parts) > 0 {
				t.markCompletedLocked(key, now)
				t.removeLocked(key, parts[0])
			}
		}
	}
	t.completed.Sweep(now)
}

func (t *sequenceTracker) markCompletedLocked(key string, now time.Time) {
	if t.completed.ActiveLen(now) >= t.opts.MaxTotalInflight {
		t.completed.Sweep(now)
	}
	if t.completed.ActiveLen(now) < t.opts.MaxTotalInflight {
		t.completed.SetUntil(key, struct{}{}, now.Add(t.nonceTT))
	}
}

func (t *sequenceTracker) removeLocked(key, ip string) {
	delete(t.states, key)
	if t.perIP[ip] > 0 {
		t.perIP[ip]--
	}
	if t.total > 0 {
		t.total--
	}
}

func splitStateKey(key string) []string {
	out := make([]string, 0, 5)
	start := 0
	for i := 0; i < len(key); i++ {
		if key[i] == 0 {
			out = append(out, key[start:i])
			start = i + 1
		}
	}
	return append(out, key[start:])
}

func jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return time.Duration(int(b[0])<<8|int(b[1])) % (max + 1)
}

func sleepSequenceInterval(ctx context.Context, index, total int, seq SequenceOptions) error {
	ctx = backgroundIfNil(ctx)
	if index+1 >= total {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(seq.PacketInterval + jitter(seq.MaxJitter)):
		return nil
	}
}
