package auth

import (
	"context"
	"net"
	"time"

	"github.com/libknock/libknock/protocol"
)

const (
	DefaultAuthTimeout     = 3 * time.Second
	DefaultTimeWindow      = 30 * time.Second
	DefaultMaxFrameSize    = 1024
	DefaultMaxAuthAttempts = 64
	MinSecretSize          = 16
)

type AuthProtocol string

const (
	AuthProtocolFrameV1    AuthProtocol = "tcp-auth-frame-v1"
	AuthProtocolEnvelopeV2 AuthProtocol = "tcp-auth-envelope-v2"
	DefaultAuthProtocol                 = AuthProtocolEnvelopeV2
)

type EnvelopeV2Config = protocol.EnvelopeV2Config
type HintMode = protocol.EnvelopeV2HintMode
type PaddingPolicy = protocol.EnvelopeV2PaddingPolicy

const (
	HintModeNone      HintMode = protocol.EnvelopeV2HintModeNone
	HintModeRouteHint HintMode = protocol.EnvelopeV2HintModeRouteHint

	PaddingPolicyNone         PaddingPolicy = protocol.EnvelopeV2PaddingNone
	PaddingPolicyRandomBucket PaddingPolicy = protocol.EnvelopeV2PaddingRandomBucket
)

type ServerConfig struct {
	// ServerPort must be set explicitly when NAT, proxies, or port forwarding make the local listener address differ from the authenticated service port.
	ServerPort         int
	Secrets            SecretResolver
	ReplayCache        ReplayCache
	AuthTimeout        time.Duration
	TimeWindow         time.Duration
	MaxFrameSize       int
	Protocol           AuthProtocol
	AcceptProtocols    []AuthProtocol
	EnvelopeV2         EnvelopeV2Config
	RequireKnock       bool
	KnockStore         KnockSessionStore
	ServerProof        bool
	FailDelayJitterMin time.Duration
	FailDelayJitterMax time.Duration
	DrainOnFailBytes   int
	DrainOnFailTimeout time.Duration
	MaxAuthAttempts    int
	Events             EventSink
	Policy             Policy
	OnAuthenticated    AuthenticatedCallback
}

type ClientConfig struct {
	ClientID string
	Secret   []byte
	// ServerPort must be set explicitly when NAT, proxies, or port forwarding make the peer address differ from the authenticated service port.
	ServerPort         int
	AuthTimeout        time.Duration
	Protocol           AuthProtocol
	EnvelopeV2         EnvelopeV2Config
	Knock              KnockSender
	Method             string
	SessionID          []byte
	Extensions         []byte
	RequireServerProof bool
}

type PeerIdentity struct {
	ClientID     string
	ClientIDHash [16]byte
}

type PeerInfo struct {
	PeerIdentity
	KeyHint    uint64
	Nonce      []byte
	Timestamp  int64
	ServerPort int
	Method     string
	SessionID  []byte
	Extensions []byte
	RemoteAddr net.Addr
	Protocol   AuthProtocol
	Flags      byte
}

type FrameMeta struct {
	Hint         uint64
	Nonce        [16]byte
	ServerPort   int
	Protocol     AuthProtocol
	HintMode     protocol.EnvelopeV2HintMode
	PrefixRandom []byte
}

type SecretResolver interface {
	ResolveCandidates(meta FrameMeta) ([]SecretCandidate, error)
}

type SecretCandidate struct {
	ClientID string
	Secret   []byte
}

type ReplayCache interface {
	CheckAndMark(clientID string, nonce []byte) error
}

type PeerInfoProvider interface {
	PeerInfo() PeerInfo
}

type KnockSender interface {
	Knock(ctx context.Context) error
}

type SessionBoundKnockSender interface {
	KnockSender
	SetSessionID([]byte)
}

type KnockSessionStore interface {
	CheckAndConsume(peer PeerInfo, remote net.Addr) error
}

type Policy interface {
	Allow(key string) bool
}

type AuthenticatedCallback func(conn net.Conn, peer PeerInfo)

type EventSink interface {
	OnAccept(remote net.Addr)
	OnAuthOK(peer PeerInfo)
	OnAuthFail(remote net.Addr, reason error)
	OnReplay(remote net.Addr, peerHint uint64)
	OnRateLimited(remote net.Addr)
}

type StaticSecrets map[string][]byte

type RotatingSecrets map[string][][]byte

func NewStaticSecretResolver(secrets map[string][]byte) StaticSecrets {
	out := make(StaticSecrets, len(secrets))
	for id, secret := range secrets {
		out[id] = append([]byte(nil), secret...)
	}
	return out
}

func (s StaticSecrets) ResolveCandidates(meta FrameMeta) ([]SecretCandidate, error) {
	out := make([]SecretCandidate, 0, len(s))
	for id, secret := range s {
		if len(secret) == 0 {
			continue
		}
		if meta.Protocol == AuthProtocolEnvelopeV2 {
			if meta.HintMode != protocol.EnvelopeV2HintModeNone {
				var prefix [protocol.EnvelopeV2PrefixSize]byte
				if len(meta.PrefixRandom) != len(prefix) {
					continue
				}
				copy(prefix[:], meta.PrefixRandom)
				if protocol.ComputeEnvelopeV2RouteHint(secret, prefix, meta.ServerPort) != meta.Hint {
					continue
				}
			}
		} else if protocol.ComputeKeyHint(secret, meta.Nonce, meta.ServerPort) != meta.Hint {
			continue
		}
		out = append(out, SecretCandidate{ClientID: id, Secret: append([]byte(nil), secret...)})
	}
	return out, nil
}

func NewRotatingSecretResolver(secrets map[string][][]byte) RotatingSecrets {
	out := make(RotatingSecrets, len(secrets))
	for id, versions := range secrets {
		out[id] = make([][]byte, 0, len(versions))
		for _, secret := range versions {
			out[id] = append(out[id], append([]byte(nil), secret...))
		}
	}
	return out
}

func (s RotatingSecrets) ResolveCandidates(meta FrameMeta) ([]SecretCandidate, error) {
	var out []SecretCandidate
	for id, versions := range s {
		for _, secret := range versions {
			if len(secret) == 0 {
				continue
			}
			if meta.Protocol == AuthProtocolEnvelopeV2 {
				if meta.HintMode != protocol.EnvelopeV2HintModeNone {
					var prefix [protocol.EnvelopeV2PrefixSize]byte
					if len(meta.PrefixRandom) != len(prefix) {
						continue
					}
					copy(prefix[:], meta.PrefixRandom)
					if protocol.ComputeEnvelopeV2RouteHint(secret, prefix, meta.ServerPort) != meta.Hint {
						continue
					}
				}
			} else if protocol.ComputeKeyHint(secret, meta.Nonce, meta.ServerPort) != meta.Hint {
				continue
			}
			out = append(out, SecretCandidate{ClientID: id, Secret: append([]byte(nil), secret...)})
		}
	}
	return out, nil
}

func (c ServerConfig) Validate() error {
	if c.MaxFrameSize <= 0 {
		c.MaxFrameSize = DefaultMaxFrameSize
	}
	if c.MaxFrameSize < protocol.HeaderSize {
		return ErrFrameTooLarge
	}
	if c.Protocol != "" && c.Protocol != AuthProtocolFrameV1 && c.Protocol != AuthProtocolEnvelopeV2 {
		return ErrUnsupportedVersion
	}
	for _, p := range c.AcceptProtocols {
		if p != AuthProtocolFrameV1 && p != AuthProtocolEnvelopeV2 {
			return ErrUnsupportedVersion
		}
	}
	if c.Protocol == AuthProtocolEnvelopeV2 || len(c.AcceptProtocols) == 0 || acceptsProtocol(c.AcceptProtocols, AuthProtocolEnvelopeV2) {
		if err := c.EnvelopeV2.WithDefaults().Validate(c.MaxFrameSize); err != nil {
			return err
		}
	}
	return nil
}

func (c ClientConfig) Validate() error {
	if c.Protocol != "" && c.Protocol != AuthProtocolFrameV1 && c.Protocol != AuthProtocolEnvelopeV2 {
		return ErrUnsupportedVersion
	}
	if c.Protocol == "" || c.Protocol == AuthProtocolEnvelopeV2 {
		return c.EnvelopeV2.WithDefaults().Validate(protocol.EnvelopeV2DefaultMaxSize)
	}
	return nil
}

type protocolSet map[AuthProtocol]struct{}

func newProtocolSet(list []AuthProtocol) protocolSet {
	out := make(protocolSet, len(list))
	for _, p := range list {
		out[p] = struct{}{}
	}
	return out
}

func acceptsProtocol(list []AuthProtocol, p AuthProtocol) bool {
	_, ok := newProtocolSet(list)[p]
	return ok
}

func (c ServerConfig) WithDefaults() ServerConfig {
	if c.AuthTimeout <= 0 {
		c.AuthTimeout = DefaultAuthTimeout
	}
	if c.TimeWindow <= 0 {
		c.TimeWindow = DefaultTimeWindow
	}
	if c.MaxFrameSize <= 0 {
		c.MaxFrameSize = DefaultMaxFrameSize
	}
	if c.Protocol == "" {
		c.Protocol = DefaultAuthProtocol
	}
	if len(c.AcceptProtocols) == 0 {
		c.AcceptProtocols = []AuthProtocol{c.Protocol}
	} else {
		c.AcceptProtocols = append([]AuthProtocol(nil), c.AcceptProtocols...)
	}
	c.EnvelopeV2 = c.EnvelopeV2.WithDefaults()
	if c.FailDelayJitterMin < 0 {
		c.FailDelayJitterMin = 0
	}
	if c.FailDelayJitterMax < 0 {
		c.FailDelayJitterMax = 0
	}
	if c.FailDelayJitterMax > 0 && c.FailDelayJitterMin > c.FailDelayJitterMax {
		c.FailDelayJitterMin, c.FailDelayJitterMax = c.FailDelayJitterMax, c.FailDelayJitterMin
	}
	if c.DrainOnFailBytes < 0 {
		c.DrainOnFailBytes = 0
	}
	if c.DrainOnFailTimeout < 0 {
		c.DrainOnFailTimeout = 0
	}
	if c.MaxAuthAttempts <= 0 {
		c.MaxAuthAttempts = DefaultMaxAuthAttempts
	}
	return c
}

func (c ClientConfig) WithDefaults() ClientConfig {
	if c.AuthTimeout <= 0 {
		c.AuthTimeout = DefaultAuthTimeout
	}
	if c.Protocol == "" {
		c.Protocol = DefaultAuthProtocol
	}
	c.EnvelopeV2 = c.EnvelopeV2.WithDefaults()
	return c
}
