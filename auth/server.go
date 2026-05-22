package auth

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/libknock/libknock/protocol"
)

type Server struct {
	cfg ServerConfig
}

// NewServer owns the replay-cache lifecycle for listener-style integrations. Use this or WrapListener when the SDK owns accepted connections.
func NewServer(cfg ServerConfig) (*Server, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Secrets == nil {
		return nil, ErrMissingSecretResolver
	}
	if cfg.ReplayCache == nil {
		cfg.ReplayCache = NewMemoryReplayCache(cfg.TimeWindow * 2)
	}
	return &Server{cfg: cfg}, nil
}

func (s *Server) Auth(ctx context.Context, conn net.Conn) (net.Conn, *PeerInfo, error) {
	if conn == nil {
		return nil, nil, ErrNilConn
	}
	if s == nil {
		_ = conn.Close()
		return nil, nil, ErrMissingSecretResolver
	}
	return serverAuthNormalized(ctx, conn, s.cfg)
}

// ServerAuth authenticates one caller-owned connection. It requires a caller-provided ReplayCache so replay state is shared across connections instead of reset per call.
func ServerAuth(ctx context.Context, conn net.Conn, cfg ServerConfig) (net.Conn, *PeerInfo, error) {
	if conn == nil {
		return nil, nil, ErrNilConn
	}
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	if cfg.ReplayCache == nil {
		_ = conn.Close()
		return nil, nil, ErrMissingReplayCache
	}
	return serverAuthNormalized(ctx, conn, cfg)
}

func serverAuthNormalized(ctx context.Context, conn net.Conn, cfg ServerConfig) (net.Conn, *PeerInfo, error) {
	if cfg.Secrets == nil {
		_ = conn.Close()
		return nil, nil, ErrMissingSecretResolver
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.Events != nil {
		cfg.Events.OnAccept(conn.RemoteAddr())
	}
	if cfg.Policy != nil && !cfg.Policy.Allow(policyKey(conn.RemoteAddr())) {
		if cfg.Events != nil {
			cfg.Events.OnRateLimited(conn.RemoteAddr())
		}
		return fail(ctx, conn, cfg, nil, ErrRateLimited, 0)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(cfg.AuthTimeout))
	}
	br := bufio.NewReader(conn)
	result, err := authenticateConfiguredProtocol(br, conn, cfg)
	if err != nil {
		return fail(ctx, conn, cfg, result.peer, err, result.hint)
	}
	peer := result.peer
	if cfg.RequireKnock {
		if cfg.KnockStore == nil {
			return fail(ctx, conn, cfg, peer, ErrKnockRequired, result.hint)
		}
		if err := cfg.KnockStore.CheckAndConsume(*peer, conn.RemoteAddr()); err != nil {
			return fail(ctx, conn, cfg, peer, errors.Join(ErrKnockRequired, err), result.hint)
		}
	}
	if result.serverProofRequested {
		if !cfg.ServerProof {
			return fail(ctx, conn, cfg, peer, ErrServerProofRequired, result.hint)
		}
		if _, err := conn.Write(result.serverProof); err != nil {
			return fail(ctx, conn, cfg, peer, err, result.hint)
		}
	}
	_ = conn.SetDeadline(time.Time{})
	// Return a clean net.Conn to the application while preserving any bytes read past the auth frame.
	clean := &authenticatedConn{bufferedConn: &bufferedConn{Conn: conn, r: br}, peer: clonePeer(*peer)}
	if cfg.Events != nil {
		cfg.Events.OnAuthOK(*peer)
	}
	if cfg.OnAuthenticated != nil {
		cfg.OnAuthenticated(clean, *peer)
	}
	return clean, peer, nil
}

type authResult struct {
	peer                 *PeerInfo
	hint                 uint64
	serverProofRequested bool
	serverProof          []byte
}

func authenticateConfiguredProtocol(br *bufio.Reader, conn net.Conn, cfg ServerConfig) (authResult, error) {
	serverPort := effectivePort(cfg.ServerPort, conn.LocalAddr())
	if acceptsProtocol(cfg.AcceptProtocols, AuthProtocolEnvelopeV2) && !acceptsProtocol(cfg.AcceptProtocols, AuthProtocolFrameV1) {
		return authenticateEnvelopeV2(br, conn, cfg, serverPort)
	}
	if acceptsProtocol(cfg.AcceptProtocols, AuthProtocolFrameV1) && !acceptsProtocol(cfg.AcceptProtocols, AuthProtocolEnvelopeV2) {
		return authenticateFrameV1(br, conn, cfg, serverPort)
	}
	if !acceptsProtocol(cfg.AcceptProtocols, AuthProtocolFrameV1) && !acceptsProtocol(cfg.AcceptProtocols, AuthProtocolEnvelopeV2) {
		return authResult{}, ErrUnsupportedVersion
	}
	b, err := br.Peek(1)
	if err != nil {
		return authResult{}, err
	}
	if b[0] == protocol.Version {
		return authenticateFrameV1(br, conn, cfg, serverPort)
	}
	return authenticateEnvelopeV2(br, conn, cfg, serverPort)
}

func authenticateFrameV1(br *bufio.Reader, conn net.Conn, cfg ServerConfig, serverPort int) (authResult, error) {
	h, sealed, err := protocol.ReadFrame(br, cfg.MaxFrameSize)
	if err != nil {
		return authResult{hint: h.KeyHint}, mapProtocolError(err)
	}
	candidates, err := cfg.Secrets.ResolveCandidates(FrameMeta{Hint: h.KeyHint, Nonce: h.Nonce, ServerPort: serverPort})
	if err != nil {
		return authResult{hint: h.KeyHint}, errors.Join(ErrSecretResolverFailed, err)
	}
	if len(candidates) == 0 {
		return authResult{hint: h.KeyHint}, ErrUnknownClient
	}
	var peer *PeerInfo
	var matchedSecret []byte
	for _, candidate := range candidates {
		p, err := authenticateCandidate(candidate, h, sealed, serverPort, conn.RemoteAddr())
		if err == nil {
			peer = p
			matchedSecret = candidate.Secret
			break
		}
	}
	if peer == nil {
		return authResult{hint: h.KeyHint}, ErrAuthFailed
	}
	if err := validatePeerCommon(cfg, peer, serverPort, conn.RemoteAddr(), h.KeyHint); err != nil {
		return authResult{peer: peer, hint: h.KeyHint}, err
	}
	res := authResult{peer: peer, hint: h.KeyHint, serverProofRequested: h.Flags&protocol.FlagServerProof != 0}
	if res.serverProofRequested {
		res.serverProof = protocol.BuildServerProof(matchedSecret, h, serverPort)
	}
	return res, nil
}

func authenticateEnvelopeV2(br *bufio.Reader, conn net.Conn, cfg ServerConfig, serverPort int) (authResult, error) {
	envCfg := cfg.EnvelopeV2.WithDefaults()
	h, err := protocol.ReadEnvelopeV2Prefix(br, protocol.EnvelopeV2HintMode(envCfg.HintMode))
	if err != nil {
		return authResult{}, mapProtocolError(err)
	}
	var candidates []SecretCandidate
	if envCfg.HintMode == protocol.EnvelopeV2HintModeRouteHint {
		var nonce [16]byte
		copy(nonce[:], h.PrefixRandom[:16])
		candidates, err = cfg.Secrets.ResolveCandidates(FrameMeta{Hint: h.RouteHint, Nonce: nonce, ServerPort: serverPort, Protocol: AuthProtocolEnvelopeV2, HintMode: envCfg.HintMode, PrefixRandom: append([]byte(nil), h.PrefixRandom[:]...)})
		if err != nil {
			return authResult{hint: h.RouteHint}, errors.Join(ErrSecretResolverFailed, err)
		}
	} else {
		candidates, err = cfg.Secrets.ResolveCandidates(FrameMeta{ServerPort: serverPort, Protocol: AuthProtocolEnvelopeV2, HintMode: envCfg.HintMode, PrefixRandom: append([]byte(nil), h.PrefixRandom[:]...)})
		if err != nil {
			return authResult{hint: h.RouteHint}, errors.Join(ErrSecretResolverFailed, err)
		}
	}
	if len(candidates) == 0 {
		return authResult{hint: h.RouteHint}, ErrUnknownClient
	}
	if envCfg.HintMode == protocol.EnvelopeV2HintModeNone && len(candidates) > cfg.MaxAuthAttempts {
		return authResult{hint: h.RouteHint}, ErrTooManyCandidates
	}
	prefixLen := protocol.EnvelopeV2PrefixSize
	if envCfg.HintMode == protocol.EnvelopeV2HintModeRouteHint {
		prefixLen += protocol.EnvelopeV2RouteHintSize
	}
	buckets := protocol.EnvelopeV2Buckets(envCfg.FrameSizeBuckets)
	attempts := 0
	for _, bucket := range buckets {
		if bucket > cfg.MaxFrameSize || bucket < prefixLen+chachaOverhead() {
			continue
		}
		need := bucket - prefixLen
		sealed, err := br.Peek(need)
		if err != nil {
			return authResult{hint: h.RouteHint}, mapProtocolError(err)
		}
		h.BucketSize = bucket
		for _, candidate := range candidates {
			if attempts >= cfg.MaxAuthAttempts {
				return authResult{hint: h.RouteHint}, ErrTooManyCandidates
			}
			attempts++
			p, err := authenticateEnvelopeV2Candidate(candidate, h, sealed, serverPort, conn.RemoteAddr())
			if err != nil {
				continue
			}
			_, _ = br.Discard(need)
			if err := validatePeerCommon(cfg, p, serverPort, conn.RemoteAddr(), h.RouteHint); err != nil {
				return authResult{peer: p, hint: h.RouteHint}, err
			}
			res := authResult{peer: p, hint: h.RouteHint, serverProofRequested: p.Flags&protocol.EnvelopeV2FlagServerProof != 0}
			if res.serverProofRequested {
				res.serverProof = protocol.BuildEnvelopeV2ServerProof(candidate.Secret, h, serverPort)
			}
			return res, nil
		}
	}
	return authResult{hint: h.RouteHint}, ErrAuthFailed
}

func chachaOverhead() int { return chacha20poly1305.Overhead }

func authenticateEnvelopeV2Candidate(candidate SecretCandidate, h protocol.EnvelopeV2Header, sealed []byte, serverPort int, remote net.Addr) (*PeerInfo, error) {
	if candidate.ClientID == "" || len(candidate.Secret) < MinSecretSize {
		return nil, ErrAuthFailed
	}
	if h.HintMode == protocol.EnvelopeV2HintModeRouteHint && protocol.ComputeEnvelopeV2RouteHint(candidate.Secret, h.PrefixRandom, serverPort) != h.RouteHint {
		return nil, ErrAuthFailed
	}
	payload, err := protocol.OpenEnvelopeV2Payload(candidate.Secret, h, serverPort, sealed)
	if err != nil {
		return nil, mapProtocolError(err)
	}
	wantHash := protocol.ComputeClientIDHash(candidate.Secret, candidate.ClientID)
	if subtle.ConstantTimeCompare(payload.ClientIDHash[:], wantHash[:]) != 1 {
		return nil, ErrAuthFailed
	}
	return newPeerInfoFromEnvelopeV2(candidate, payload, h, remote), nil
}

func validatePeerCommon(cfg ServerConfig, peer *PeerInfo, serverPort int, remote net.Addr, hint uint64) error {
	if serverPort > 0 && peer.ServerPort != serverPort {
		return ErrAuthFailed
	}
	age := time.Since(time.UnixMilli(peer.Timestamp))
	if age < -cfg.TimeWindow || age > cfg.TimeWindow {
		return ErrTimeSkew
	}
	if err := cfg.ReplayCache.CheckAndMark(peer.ClientID, peer.Nonce); err != nil {
		if cfg.Events != nil {
			switch {
			case errors.Is(err, ErrReplayDetected):
				cfg.Events.OnReplay(remote, hint)
			case errors.Is(err, ErrReplayCacheFull):
				length, capacity := replayCacheStats(cfg.ReplayCache)
				cfg.Events.OnReplayCacheFull(remote, hint, length, capacity)
			}
		}
		return err
	}
	return nil
}

func authenticateCandidate(candidate SecretCandidate, h protocol.Header, sealed []byte, serverPort int, remote net.Addr) (*PeerInfo, error) {
	if candidate.ClientID == "" || len(candidate.Secret) < MinSecretSize {
		return nil, ErrAuthFailed
	}
	if protocol.ComputeKeyHint(candidate.Secret, h.Nonce, serverPort) != h.KeyHint {
		return nil, ErrAuthFailed
	}
	plain, err := protocol.OpenPayload(candidate.Secret, h, sealed)
	if err != nil {
		return nil, ErrAuthFailed
	}
	payload, err := protocol.DecodePayload(plain)
	if err != nil {
		return nil, mapProtocolError(err)
	}
	wantHash := protocol.ComputeClientIDHash(candidate.Secret, candidate.ClientID)
	if subtle.ConstantTimeCompare(payload.ClientIDHash[:], wantHash[:]) != 1 {
		return nil, ErrAuthFailed
	}
	return newPeerInfoFromV1(candidate, payload, h, remote), nil
}

func newPeerInfoFromV1(candidate SecretCandidate, payload protocol.Payload, h protocol.Header, remote net.Addr) *PeerInfo {
	return &PeerInfo{
		PeerIdentity: PeerIdentity{ClientID: candidate.ClientID, ClientIDHash: payload.ClientIDHash},
		KeyHint:      h.KeyHint,
		Nonce:        append([]byte(nil), h.Nonce[:]...),
		Timestamp:    payload.TimestampUnixMS,
		ServerPort:   payload.ServerPort,
		Method:       payload.Method,
		SessionID:    payload.SessionID,
		Extensions:   payload.Extensions,
		RemoteAddr:   remote,
	}
}

func newPeerInfoFromEnvelopeV2(candidate SecretCandidate, payload protocol.EnvelopeV2Payload, h protocol.EnvelopeV2Header, remote net.Addr) *PeerInfo {
	return &PeerInfo{
		PeerIdentity: PeerIdentity{ClientID: candidate.ClientID, ClientIDHash: payload.ClientIDHash},
		KeyHint:      h.RouteHint,
		Nonce:        append([]byte(nil), h.PrefixRandom[:]...),
		Timestamp:    payload.TimestampUnixMS,
		ServerPort:   payload.ServerPort,
		Method:       payload.Method,
		SessionID:    payload.SessionID,
		Extensions:   payload.Extensions,
		RemoteAddr:   remote,
		Protocol:     AuthProtocolEnvelopeV2,
		Flags:        payload.Flags,
	}
}

// fail reports precise errors to the caller's EventSink while keeping the peer-facing behavior a quiet close with optional jitter/drain.
func fail(ctx context.Context, conn net.Conn, cfg ServerConfig, peer *PeerInfo, err error, hint uint64) (net.Conn, *PeerInfo, error) {
	err = publicError(err)
	if cfg.Events != nil {
		remote := conn.RemoteAddr()
		if peer != nil && peer.RemoteAddr != nil {
			remote = peer.RemoteAddr
		}
		cfg.Events.OnAuthFail(remote, err)
	}
	drainOnFail(ctx, conn, cfg)
	delayOnFail(ctx, cfg)
	_ = conn.Close()
	return nil, nil, err
}

func drainOnFail(ctx context.Context, conn net.Conn, cfg ServerConfig) {
	if cfg.DrainOnFailBytes <= 0 || cfg.DrainOnFailTimeout <= 0 {
		return
	}
	if deadline, ok := ctx.Deadline(); ok {
		if max := time.Now().Add(cfg.DrainOnFailTimeout); max.Before(deadline) {
			_ = conn.SetReadDeadline(max)
		} else {
			_ = conn.SetReadDeadline(deadline)
		}
	} else {
		_ = conn.SetReadDeadline(time.Now().Add(cfg.DrainOnFailTimeout))
	}
	_, _ = io.CopyN(io.Discard, conn, int64(cfg.DrainOnFailBytes))
}

func delayOnFail(ctx context.Context, cfg ServerConfig) {
	max := cfg.FailDelayJitterMax
	if max <= 0 {
		return
	}
	min := cfg.FailDelayJitterMin
	if min > max {
		min, max = max, min
	}
	d := min
	if spread := max - min; spread > 0 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err == nil {
			d += time.Duration(binary.BigEndian.Uint64(b[:]) % uint64(spread+1))
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func policyKey(addr net.Addr) string {
	if addr == nil {
		return "unknown:nil"
	}
	if tcp, ok := addr.(*net.TCPAddr); ok {
		if tcp.IP != nil {
			return tcp.IP.String()
		}
		return "unknown:tcp"
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil && host != "" {
		return host
	}
	if addr.String() == "" {
		return "unknown:" + addr.Network()
	}
	return addr.Network() + ":" + addr.String()
}

func publicError(err error) error {
	if errors.Is(err, ErrNilConn) || errors.Is(err, ErrInvalidFrame) || errors.Is(err, ErrFrameTooLarge) || errors.Is(err, ErrUnknownClient) || errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrReplayDetected) || errors.Is(err, ErrTimeSkew) || errors.Is(err, ErrKnockRequired) || errors.Is(err, ErrUnsupportedVersion) || errors.Is(err, ErrUnsupportedFlags) || errors.Is(err, ErrSecretResolverFailed) || errors.Is(err, ErrRateLimited) || errors.Is(err, ErrServerProofRequired) || errors.Is(err, ErrServerProofFailed) || errors.Is(err, ErrTooManyCandidates) {
		return err
	}
	return ErrAuthFailed
}

func mapProtocolError(err error) error {
	if errors.Is(err, protocol.ErrFrameTooLarge) {
		return ErrFrameTooLarge
	}
	if errors.Is(err, protocol.ErrUnsupportedVersion) {
		return ErrUnsupportedVersion
	}
	if errors.Is(err, protocol.ErrUnsupportedFlags) {
		return ErrUnsupportedFlags
	}
	if errors.Is(err, protocol.ErrInvalidFrame) {
		return ErrInvalidFrame
	}
	return err
}

func replayCacheStats(cache ReplayCache) (int, int) {
	stats, ok := cache.(ReplayCacheStats)
	if !ok {
		return 0, 0
	}
	return stats.Len(), stats.Cap()
}
