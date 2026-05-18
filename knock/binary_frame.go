package knock

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/internal/codec"
	"github.com/libknock/libknock/internal/cryptox"
	"github.com/libknock/libknock/protocol"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KnockFrameVersion        = byte(1)
	KnockFrameHeaderSize     = 16 + 8 + 2 + 1 + 1
	DefaultMaxKnockFrameSize = 1024
	KnockNonceBytes          = 16
	KnockSessionIDMinBytes   = 16
	KnockSequenceIDBytes     = 16
	KnockClientRandomBytes   = 16

	KnockFrameTypeUDP         = byte(1)
	KnockFrameTypeUDPSequence = byte(2)

	KnockFlagSequence   = byte(1 << 0)
	KnockFlagSession    = byte(1 << 1)
	KnockFlagExtensions = byte(1 << 2)
	allowedKnockFlags   = KnockFlagSequence | KnockFlagSession | KnockFlagExtensions
)

type KnockFrameOptions struct {
	ClientID      string
	Secret        []byte
	Method        string
	ServerPort    int
	SessionID     []byte
	SequenceID    []byte
	SequenceIndex int
	SequenceTotal int
	ClientRandom  []byte
	Extensions    []protocol.TLV
	Timestamp     time.Time
	MaxFrameSize  int
}

type ServerConfig struct {
	Clients       []ClientSecret
	ServerPort    int
	Method        string
	TimeWindow    time.Duration
	MaxFrameSize  int
	ReplayCache   auth.ReplayCache
	AllowSequence bool
}

type KnockInfo struct {
	ClientID      string
	ClientIDHash  []byte
	Method        string
	ServerPort    int
	Timestamp     time.Time
	SessionID     []byte
	SequenceID    []byte
	SequenceIndex int
	SequenceTotal int
	ClientRandom  []byte
	Extensions    []protocol.TLV
	Nonce         []byte
	KeyHint       uint64
	FrameType     byte
	Flags         byte
}

type knockFrameHeader struct {
	Nonce     [KnockNonceBytes]byte
	KeyHint   uint64
	SealedLen uint16
	Flags     byte
	Reserved  byte
}

type knockPayload struct {
	FrameType     byte
	ClientIDHash  [16]byte
	TimestampMS   int64
	Method        string
	ServerPort    int
	SessionID     []byte
	SequenceID    []byte
	SequenceIndex int
	SequenceTotal int
	ClientRandom  []byte
	Extensions    []protocol.TLV
}

func BuildKnockFrame(opts KnockFrameOptions) ([]byte, error) {
	if opts.Method == "" {
		opts.Method = UDPMethod
	}
	if opts.Timestamp.IsZero() {
		opts.Timestamp = time.Now()
	}
	if opts.MaxFrameSize <= 0 {
		opts.MaxFrameSize = DefaultMaxKnockFrameSize
	}
	if err := ValidateClientSecret(ClientSecret{ClientID: opts.ClientID, Secret: opts.Secret}); err != nil {
		return nil, err
	}
	if err := validateProtectedPort(opts.ServerPort); err != nil {
		return nil, err
	}
	payload := knockPayload{
		FrameType:    KnockFrameTypeUDP,
		ClientIDHash: ComputeKnockClientIDHash(opts.Secret, opts.ClientID),
		TimestampMS:  opts.Timestamp.UnixMilli(),
		Method:       opts.Method,
		ServerPort:   opts.ServerPort,
		SessionID:    append([]byte(nil), opts.SessionID...),
	}
	if len(opts.SessionID) > 0 && len(opts.SessionID) < KnockSessionIDMinBytes {
		return nil, auth.ErrInvalidFrame
	}
	if opts.SequenceTotal > 0 || len(opts.SequenceID) > 0 {
		payload.FrameType = KnockFrameTypeUDPSequence
		if len(opts.SequenceID) != KnockSequenceIDBytes {
			return nil, auth.ErrInvalidFrame
		}
		if opts.SequenceTotal < 2 || opts.SequenceTotal > DefaultSequenceMaxParts || opts.SequenceIndex < 0 || opts.SequenceIndex >= opts.SequenceTotal {
			return nil, auth.ErrInvalidFrame
		}
		payload.SequenceID = append([]byte(nil), opts.SequenceID...)
		payload.SequenceIndex = opts.SequenceIndex
		payload.SequenceTotal = opts.SequenceTotal
	}
	if len(opts.ClientRandom) == 0 {
		opts.ClientRandom = make([]byte, KnockClientRandomBytes)
		if _, err := rand.Read(opts.ClientRandom); err != nil {
			return nil, err
		}
	}
	payload.ClientRandom = append([]byte(nil), opts.ClientRandom...)
	payload.Extensions = append([]protocol.TLV(nil), opts.Extensions...)
	plain, err := encodeKnockPayload(payload)
	if err != nil {
		return nil, err
	}
	var h knockFrameHeader
	if _, err := rand.Read(h.Nonce[:]); err != nil {
		return nil, err
	}
	h.KeyHint = ComputeKnockKeyHint(opts.Secret, h.Nonce, opts.ServerPort)
	if payload.FrameType == KnockFrameTypeUDPSequence {
		h.Flags |= KnockFlagSequence
	}
	if len(payload.SessionID) > 0 {
		h.Flags |= KnockFlagSession
	}
	if len(payload.Extensions) > 0 {
		h.Flags |= KnockFlagExtensions
	}
	sealedLen := len(plain) + chacha20poly1305.Overhead
	if sealedLen > 65535 || KnockFrameHeaderSize+sealedLen > opts.MaxFrameSize {
		return nil, auth.ErrFrameTooLarge
	}
	h.SealedLen = uint16(sealedLen)
	sealed, err := sealKnockPayload(opts.Secret, h, opts.ServerPort, plain)
	if err != nil {
		return nil, err
	}
	out := make([]byte, KnockFrameHeaderSize+len(sealed))
	encodeKnockHeader(out[:KnockFrameHeaderSize], h)
	copy(out[KnockFrameHeaderSize:], sealed)
	return out, nil
}

func OpenKnockFrame(packet []byte, cfg ServerConfig) (*KnockInfo, error) {
	if cfg.MaxFrameSize <= 0 {
		cfg.MaxFrameSize = DefaultMaxKnockFrameSize
	}
	if cfg.TimeWindow <= 0 {
		cfg.TimeWindow = 30 * time.Second
	}
	if err := validateProtectedPort(cfg.ServerPort); err != nil {
		return nil, err
	}
	if len(packet) < KnockFrameHeaderSize {
		return nil, auth.ErrInvalidFrame
	}
	if len(packet) > cfg.MaxFrameSize {
		return nil, auth.ErrFrameTooLarge
	}
	h := decodeKnockHeader(packet[:KnockFrameHeaderSize])
	if h.Reserved != 0 {
		return nil, auth.ErrInvalidFrame
	}
	if h.Flags&^allowedKnockFlags != 0 {
		return nil, auth.ErrUnsupportedFlags
	}
	if h.SealedLen == 0 {
		return nil, auth.ErrInvalidFrame
	}
	if KnockFrameHeaderSize+int(h.SealedLen) != len(packet) {
		if KnockFrameHeaderSize+int(h.SealedLen) > cfg.MaxFrameSize {
			return nil, auth.ErrFrameTooLarge
		}
		return nil, auth.ErrInvalidFrame
	}
	sealed := packet[KnockFrameHeaderSize:]
	var sawHint bool
	for _, client := range cfg.Clients {
		if ValidateClientSecret(client) != nil {
			continue
		}
		if ComputeKnockKeyHint(client.Secret, h.Nonce, cfg.ServerPort) != h.KeyHint {
			continue
		}
		sawHint = true
		plain, err := openKnockPayload(client.Secret, h, cfg.ServerPort, sealed)
		if err != nil {
			continue
		}
		payload, err := decodeKnockPayload(plain)
		if err != nil {
			return nil, err
		}
		wantHash := ComputeKnockClientIDHash(client.Secret, client.ClientID)
		if !cryptox.ConstantTimeEqual(payload.ClientIDHash[:], wantHash[:]) {
			continue
		}
		if payload.ServerPort != cfg.ServerPort {
			return nil, auth.ErrAuthFailed
		}
		if err := validateKnockFlags(h.Flags, payload); err != nil {
			return nil, err
		}
		if cfg.Method != "" && payload.Method != cfg.Method {
			return nil, auth.ErrAuthFailed
		}
		if payload.FrameType == KnockFrameTypeUDPSequence {
			if !cfg.AllowSequence {
				return nil, auth.ErrInvalidFrame
			}
			if len(payload.SequenceID) != KnockSequenceIDBytes || payload.SequenceTotal < 2 || payload.SequenceTotal > DefaultSequenceMaxParts || payload.SequenceIndex < 0 || payload.SequenceIndex >= payload.SequenceTotal {
				return nil, auth.ErrInvalidFrame
			}
		} else if payload.FrameType != KnockFrameTypeUDP {
			return nil, auth.ErrInvalidFrame
		}
		ts := time.UnixMilli(payload.TimestampMS)
		age := time.Since(ts)
		if age < -cfg.TimeWindow || age > cfg.TimeWindow {
			return nil, auth.ErrTimeSkew
		}
		if cfg.ReplayCache != nil {
			if err := cfg.ReplayCache.CheckAndMark(client.ClientID, h.Nonce[:]); err != nil {
				return nil, err
			}
		}
		return &KnockInfo{
			ClientID:      client.ClientID,
			ClientIDHash:  append([]byte(nil), payload.ClientIDHash[:]...),
			Method:        payload.Method,
			ServerPort:    payload.ServerPort,
			Timestamp:     ts,
			SessionID:     append([]byte(nil), payload.SessionID...),
			SequenceID:    append([]byte(nil), payload.SequenceID...),
			SequenceIndex: payload.SequenceIndex,
			SequenceTotal: payload.SequenceTotal,
			ClientRandom:  append([]byte(nil), payload.ClientRandom...),
			Extensions:    append([]protocol.TLV(nil), payload.Extensions...),
			Nonce:         append([]byte(nil), h.Nonce[:]...),
			KeyHint:       h.KeyHint,
			FrameType:     payload.FrameType,
			Flags:         h.Flags,
		}, nil
	}
	if sawHint {
		return nil, auth.ErrAuthFailed
	}
	return nil, auth.ErrUnknownClient
}

func validateKnockFlags(flags byte, payload knockPayload) error {
	if flags&^allowedKnockFlags != 0 {
		return auth.ErrUnsupportedFlags
	}
	if (flags&KnockFlagSequence != 0) != (payload.FrameType == KnockFrameTypeUDPSequence) {
		return auth.ErrInvalidFrame
	}
	if (flags&KnockFlagSession != 0) != (len(payload.SessionID) >= KnockSessionIDMinBytes) {
		return auth.ErrInvalidFrame
	}
	if (flags&KnockFlagExtensions != 0) != (len(payload.Extensions) > 0) {
		return auth.ErrInvalidFrame
	}
	return nil
}

func ComputeKnockKeyHint(secret []byte, nonce [KnockNonceBytes]byte, serverPort int) uint64 {
	if serverPort < 1 || serverPort > 65535 {
		return 0
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(serverPort))
	data := append(append([]byte("libknock udp-knock hint v1"), nonce[:]...), port[:]...)
	return cryptox.HMACTrunc64(secret, data)
}

func ComputeKnockClientIDHash(secret []byte, clientID string) [16]byte {
	return cryptox.HMACTrunc128(secret, append([]byte("libknock client-id v1"), clientID...))
}

func encodeKnockHeader(dst []byte, h knockFrameHeader) {
	if len(dst) < KnockFrameHeaderSize {
		return
	}
	copy(dst[0:16], h.Nonce[:])
	binary.BigEndian.PutUint64(dst[16:24], h.KeyHint)
	binary.BigEndian.PutUint16(dst[24:26], h.SealedLen)
	dst[26] = h.Flags
	dst[27] = h.Reserved
}

func decodeKnockHeader(src []byte) knockFrameHeader {
	var h knockFrameHeader
	if len(src) < KnockFrameHeaderSize {
		return h
	}
	copy(h.Nonce[:], src[0:16])
	h.KeyHint = binary.BigEndian.Uint64(src[16:24])
	h.SealedLen = binary.BigEndian.Uint16(src[24:26])
	h.Flags = src[26]
	h.Reserved = src[27]
	return h
}

func sealKnockPayload(secret []byte, h knockFrameHeader, serverPort int, plain []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(deriveKnockAEADKey(secret, h.Nonce))
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, h.Nonce[:chacha20poly1305.NonceSize], plain, knockAAD(h, serverPort)), nil
}

func openKnockPayload(secret []byte, h knockFrameHeader, serverPort int, sealed []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(deriveKnockAEADKey(secret, h.Nonce))
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, h.Nonce[:chacha20poly1305.NonceSize], sealed, knockAAD(h, serverPort))
}

func deriveKnockAEADKey(secret []byte, nonce [KnockNonceBytes]byte) []byte {
	return cryptox.MustHKDFSHA256(secret, nonce[:], []byte("libknock udp-knock frame v1"), chacha20poly1305.KeySize)
}

func knockAAD(h knockFrameHeader, serverPort int) []byte {
	out := make([]byte, 0, KnockFrameHeaderSize+1+2)
	var header [KnockFrameHeaderSize]byte
	encodeKnockHeader(header[:], h)
	out = append(out, header[:]...)
	out = append(out, KnockFrameVersion)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(serverPort))
	out = append(out, port[:]...)
	return out
}

func encodeKnockPayload(p knockPayload) ([]byte, error) {
	if p.Method == "" || len(p.Method) > 255 || len(p.SessionID) > 255 || len(p.SequenceID) > 255 || len(p.ClientRandom) > 255 {
		return nil, auth.ErrInvalidFrame
	}
	if p.ServerPort < 1 || p.ServerPort > 65535 {
		return nil, auth.ErrInvalidFrame
	}
	ext, err := protocol.EncodeTLVs(p.Extensions)
	if err != nil {
		return nil, mapProtocolFrameError(err)
	}
	if len(ext) > 65535 {
		return nil, auth.ErrFrameTooLarge
	}
	buf := bytes.NewBuffer(make([]byte, 0, 1+16+8+1+len(p.Method)+2+1+len(p.SessionID)+1+len(p.SequenceID)+3+len(p.ClientRandom)+2+len(ext)))
	buf.WriteByte(p.FrameType)
	buf.Write(p.ClientIDHash[:])
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(p.TimestampMS))
	buf.Write(tmp[:])
	buf.WriteByte(byte(len(p.Method)))
	buf.WriteString(p.Method)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(p.ServerPort))
	buf.Write(port[:])
	buf.WriteByte(byte(len(p.SessionID)))
	buf.Write(p.SessionID)
	buf.WriteByte(byte(len(p.SequenceID)))
	buf.Write(p.SequenceID)
	buf.WriteByte(byte(p.SequenceIndex))
	buf.WriteByte(byte(p.SequenceTotal))
	buf.WriteByte(byte(len(p.ClientRandom)))
	buf.Write(p.ClientRandom)
	var extLen [2]byte
	binary.BigEndian.PutUint16(extLen[:], uint16(len(ext)))
	buf.Write(extLen[:])
	buf.Write(ext)
	return buf.Bytes(), nil
}

func decodeKnockPayload(raw []byte) (knockPayload, error) {
	var p knockPayload
	r := codec.NewReader(raw, auth.ErrInvalidFrame)
	var err error
	if p.FrameType, err = r.ReadByte(); err != nil {
		return p, err
	}
	id, err := r.ReadFixed(16)
	if err != nil {
		return p, err
	}
	copy(p.ClientIDHash[:], id)
	ts, err := r.ReadUint64()
	if err != nil {
		return p, err
	}
	p.TimestampMS = int64(ts)
	methodLen, err := r.ReadByte()
	if err != nil || methodLen == 0 {
		return p, auth.ErrInvalidFrame
	}
	method, err := r.ReadVarBytes(int(methodLen), false)
	if err != nil {
		return p, err
	}
	p.Method = string(method)
	port, err := r.ReadUint16()
	if err != nil {
		return p, err
	}
	p.ServerPort = int(port)
	if p.SessionID, err = readByteLen(r); err != nil {
		return p, err
	}
	if p.SequenceID, err = readByteLen(r); err != nil {
		return p, err
	}
	if p.SequenceIndex, p.SequenceTotal, err = readSequenceIndexes(r); err != nil {
		return p, err
	}
	if p.ClientRandom, err = readByteLen(r); err != nil {
		return p, err
	}
	extLen, err := r.ReadUint16()
	if err != nil {
		return p, err
	}
	if int(extLen) != r.Remaining() {
		return p, auth.ErrInvalidFrame
	}
	ext, err := r.ReadFixed(int(extLen))
	if err != nil {
		return p, err
	}
	tlvs, err := protocol.DecodeTLVs(ext)
	if err != nil {
		return p, mapProtocolFrameError(err)
	}
	p.Extensions = tlvs
	if len(p.SessionID) > 0 && len(p.SessionID) < KnockSessionIDMinBytes {
		return p, auth.ErrInvalidFrame
	}
	return p, nil
}

func readByteLen(r *codec.BinaryReader) ([]byte, error) {
	n, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	return r.ReadVarBytes(int(n), true)
}

func readSequenceIndexes(r *codec.BinaryReader) (int, int, error) {
	index, err := r.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	total, err := r.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	return int(index), int(total), nil
}

func mapProtocolFrameError(err error) error {
	if errors.Is(err, protocol.ErrFrameTooLarge) {
		return auth.ErrFrameTooLarge
	}
	if errors.Is(err, protocol.ErrInvalidFrame) {
		return auth.ErrInvalidFrame
	}
	return err
}

func requireSessionID(sessionID []byte) error {
	if len(sessionID) < KnockSessionIDMinBytes {
		return fmt.Errorf("session_id must be at least %d bytes", KnockSessionIDMinBytes)
	}
	return nil
}
