package auth

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/libknock/libknock/protocol"
)

func ClientAuth(ctx context.Context, conn net.Conn, cfg ClientConfig) error {
	_, err := ClientAuthWithInfo(ctx, conn, cfg)
	return err
}

func ClientAuthWithInfo(ctx context.Context, conn net.Conn, cfg ClientConfig) (*PeerInfo, error) {
	if conn == nil {
		return nil, ErrNilConn
	}
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if cfg.ClientID == "" || len(cfg.ClientID) > 65535 {
		_ = conn.Close()
		return nil, ErrInvalidClientID
	}
	if len(cfg.Secret) < MinSecretSize {
		_ = conn.Close()
		return nil, ErrInvalidSecret
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(cfg.AuthTimeout))
	}
	serverPort := effectivePort(cfg.ServerPort, conn.RemoteAddr())
	flags := byte(0)
	if cfg.RequireServerProof {
		flags |= protocol.FlagServerProof
	}
	now := time.Now()
	if cfg.Protocol == AuthProtocolEnvelopeV2 {
		frame, header, err := buildEnvelopeOptions(cfg, serverPort, now, flags)
		if err != nil {
			_ = conn.Close()
			return nil, mapProtocolError(err)
		}
		if _, err := conn.Write(frame); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if cfg.RequireServerProof {
			proof := make([]byte, protocol.ServerProofSize)
			if _, err := io.ReadFull(conn, proof); err != nil {
				_ = conn.Close()
				return nil, ErrServerProofFailed
			}
			if err := protocol.VerifyEnvelopeV2ServerProof(proof, cfg.Secret, header, serverPort); err != nil {
				_ = conn.Close()
				return nil, ErrServerProofFailed
			}
		}
		_ = conn.SetDeadline(time.Time{})
		return newClientEnvelopePeer(cfg, header, serverPort, now, flags, conn.RemoteAddr()), nil
	}
	frame, header, err := buildClientFrameOptions(cfg, serverPort, now, flags)
	if err != nil {
		_ = conn.Close()
		return nil, mapProtocolError(err)
	}
	if _, err := conn.Write(frame); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if cfg.RequireServerProof {
		proof := make([]byte, protocol.ServerProofSize)
		if _, err := io.ReadFull(conn, proof); err != nil {
			_ = conn.Close()
			return nil, ErrServerProofFailed
		}
		if err := protocol.VerifyServerProof(proof, cfg.Secret, header, serverPort); err != nil {
			_ = conn.Close()
			return nil, ErrServerProofFailed
		}
	}
	_ = conn.SetDeadline(time.Time{})
	return newClientFramePeer(cfg, header, serverPort, now, conn.RemoteAddr()), nil
}

func buildClientFrameOptions(cfg ClientConfig, serverPort int, now time.Time, flags byte) ([]byte, protocol.Header, error) {
	return protocol.BuildFrame(cfg.ClientID, cfg.Secret, serverPort, now, flags, cfg.Method, cfg.SessionID, cfg.Extensions)
}

func buildEnvelopeOptions(cfg ClientConfig, serverPort int, now time.Time, flags byte) ([]byte, protocol.EnvelopeV2Header, error) {
	return protocol.BuildEnvelopeV2(cfg.ClientID, cfg.Secret, serverPort, now, flags, cfg.Method, cfg.SessionID, cfg.Extensions, cfg.EnvelopeV2)
}

func newClientFramePeer(cfg ClientConfig, h protocol.Header, serverPort int, now time.Time, remote net.Addr) *PeerInfo {
	return &PeerInfo{
		PeerIdentity: PeerIdentity{ClientID: cfg.ClientID, ClientIDHash: protocol.ComputeClientIDHash(cfg.Secret, cfg.ClientID)},
		KeyHint:      h.KeyHint,
		Nonce:        append([]byte(nil), h.Nonce[:]...),
		Timestamp:    now.UnixMilli(),
		ServerPort:   serverPort,
		Method:       cfg.Method,
		SessionID:    append([]byte(nil), cfg.SessionID...),
		Extensions:   append([]byte(nil), cfg.Extensions...),
		RemoteAddr:   remote,
	}
}

func newClientEnvelopePeer(cfg ClientConfig, h protocol.EnvelopeV2Header, serverPort int, now time.Time, flags byte, remote net.Addr) *PeerInfo {
	return &PeerInfo{
		PeerIdentity: PeerIdentity{ClientID: cfg.ClientID, ClientIDHash: protocol.ComputeClientIDHash(cfg.Secret, cfg.ClientID)},
		KeyHint:      h.RouteHint,
		Nonce:        append([]byte(nil), h.PrefixRandom[:]...),
		Timestamp:    now.UnixMilli(),
		ServerPort:   serverPort,
		Method:       cfg.Method,
		SessionID:    append([]byte(nil), cfg.SessionID...),
		Extensions:   append([]byte(nil), cfg.Extensions...),
		RemoteAddr:   remote,
		Protocol:     AuthProtocolEnvelopeV2,
		Flags:        flags,
	}
}
