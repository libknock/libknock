package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/libknock/libknock/internal/codec"
	"github.com/libknock/libknock/internal/cryptox"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	EnvelopeV2Version          = byte(2)
	EnvelopeV2PrefixSize       = 24
	EnvelopeV2RouteHintSize    = 8
	EnvelopeV2DefaultMaxSize   = 512
	EnvelopeV2ProtocolLabel    = "tcp-auth-envelope-v2"
	EnvelopeV2FlagServerProof  = FlagServerProof
	EnvelopeV2DefaultMinBucket = 128
)

var EnvelopeV2DefaultBuckets = []int{128, 192, 256, 384, 512}

type EnvelopeV2HintMode string

const (
	EnvelopeV2HintModeNone      EnvelopeV2HintMode = "none"
	EnvelopeV2HintModeRouteHint EnvelopeV2HintMode = "route-hint"
)

type EnvelopeV2PaddingPolicy string

const (
	EnvelopeV2PaddingNone         EnvelopeV2PaddingPolicy = "none"
	EnvelopeV2PaddingRandomBucket EnvelopeV2PaddingPolicy = "random-bucket"
)

type EnvelopeV2Config struct {
	HintMode         EnvelopeV2HintMode
	FrameSizeBuckets []int
	PaddingPolicy    EnvelopeV2PaddingPolicy
}

type EnvelopeV2Header struct {
	PrefixRandom [EnvelopeV2PrefixSize]byte
	RouteHint    uint64
	BucketSize   int
	HintMode     EnvelopeV2HintMode
}

type EnvelopeV2Payload struct {
	Version         byte
	Flags           byte
	TimestampUnixMS int64
	ClientIDHash    [16]byte
	ServerPort      int
	Method          string
	SessionID       []byte
	Extensions      []byte
}

func (c EnvelopeV2Config) Validate(maxFrameSize int) error {
	c = c.WithDefaults()
	if c.HintMode != EnvelopeV2HintModeRouteHint && c.HintMode != EnvelopeV2HintModeNone {
		return ErrInvalidFrame
	}
	if c.PaddingPolicy != EnvelopeV2PaddingRandomBucket && c.PaddingPolicy != EnvelopeV2PaddingNone {
		return ErrInvalidFrame
	}
	if maxFrameSize <= 0 {
		maxFrameSize = EnvelopeV2DefaultMaxSize
	}
	buckets := EnvelopeV2Buckets(c.FrameSizeBuckets)
	if len(buckets) == 0 {
		return ErrFrameTooLarge
	}
	for _, bucket := range buckets {
		if bucket > maxFrameSize || !EnvelopeV2SupportedBucket(bucket) {
			return ErrFrameTooLarge
		}
	}
	return nil
}

func (c EnvelopeV2Config) WithDefaults() EnvelopeV2Config {
	if c.HintMode == "" {
		c.HintMode = EnvelopeV2HintModeRouteHint
	}
	if len(c.FrameSizeBuckets) == 0 {
		c.FrameSizeBuckets = append([]int(nil), EnvelopeV2DefaultBuckets...)
	} else {
		c.FrameSizeBuckets = append([]int(nil), c.FrameSizeBuckets...)
	}
	if c.PaddingPolicy == "" {
		c.PaddingPolicy = EnvelopeV2PaddingRandomBucket
	}
	return c
}

func BuildEnvelopeV2(clientID string, secret []byte, serverPort int, now time.Time, flags byte, method string, sessionID, extensions []byte, cfg EnvelopeV2Config) ([]byte, EnvelopeV2Header, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(EnvelopeV2DefaultMaxSize); err != nil {
		return nil, EnvelopeV2Header{}, err
	}
	if clientID == "" || len(secret) < MinSecretSize {
		return nil, EnvelopeV2Header{}, ErrInvalidFrame
	}
	if flags&^EnvelopeV2FlagServerProof != 0 {
		return nil, EnvelopeV2Header{}, ErrUnsupportedFlags
	}
	if serverPort < 0 || serverPort > 65535 {
		return nil, EnvelopeV2Header{}, fmt.Errorf("server port out of range: %d", serverPort)
	}
	var h EnvelopeV2Header
	h.HintMode = cfg.HintMode
	for {
		if _, err := rand.Read(h.PrefixRandom[:]); err != nil {
			return nil, EnvelopeV2Header{}, err
		}
		if h.PrefixRandom[0] != Version {
			break
		}
	}
	if cfg.HintMode == EnvelopeV2HintModeRouteHint {
		h.RouteHint = ComputeEnvelopeV2RouteHint(secret, h.PrefixRandom, serverPort)
	} else if cfg.HintMode != EnvelopeV2HintModeNone {
		return nil, EnvelopeV2Header{}, ErrInvalidFrame
	}
	payload := EnvelopeV2Payload{Version: EnvelopeV2Version, Flags: flags, TimestampUnixMS: now.UnixMilli(), ClientIDHash: ComputeClientIDHash(secret, clientID), ServerPort: serverPort, Method: method, SessionID: sessionID, Extensions: extensions}
	plain, err := EncodeEnvelopeV2Payload(payload)
	if err != nil {
		return nil, EnvelopeV2Header{}, err
	}
	minSize := EnvelopeV2PrefixSize + len(plain) + chacha20poly1305.Overhead
	if cfg.HintMode == EnvelopeV2HintModeRouteHint {
		minSize += EnvelopeV2RouteHintSize
	}
	candidates := make([]int, 0, len(cfg.FrameSizeBuckets))
	for _, bucket := range EnvelopeV2Buckets(cfg.FrameSizeBuckets) {
		if bucket >= minSize {
			candidates = append(candidates, bucket)
		}
	}
	if len(candidates) == 0 {
		return nil, EnvelopeV2Header{}, ErrFrameTooLarge
	}
	idx, err := randInt(len(candidates))
	if err != nil {
		return nil, EnvelopeV2Header{}, err
	}
	bucket := candidates[idx]
	h.BucketSize = bucket
	prefix := EnvelopeV2PrefixSize
	if cfg.HintMode == EnvelopeV2HintModeRouteHint {
		prefix += EnvelopeV2RouteHintSize
	}
	sealedLen := bucket - prefix
	paddingLen := sealedLen - chacha20poly1305.Overhead - len(plain) - 2
	if paddingLen < 0 {
		return nil, EnvelopeV2Header{}, ErrFrameTooLarge
	}
	body := make([]byte, 0, len(plain)+2+paddingLen)
	body = append(body, plain...)
	var pbuf [2]byte
	binary.BigEndian.PutUint16(pbuf[:], uint16(paddingLen))
	body = append(body, pbuf[:]...)
	if paddingLen > 0 {
		padding := make([]byte, paddingLen)
		if cfg.PaddingPolicy == EnvelopeV2PaddingRandomBucket {
			if _, err := rand.Read(padding); err != nil {
				return nil, EnvelopeV2Header{}, err
			}
		} else if cfg.PaddingPolicy != EnvelopeV2PaddingNone {
			return nil, EnvelopeV2Header{}, ErrInvalidFrame
		}
		body = append(body, padding...)
	}
	sealed, err := SealEnvelopeV2Payload(secret, h, serverPort, body)
	if err != nil {
		return nil, EnvelopeV2Header{}, err
	}
	out := make([]byte, 0, bucket)
	out = append(out, h.PrefixRandom[:]...)
	if cfg.HintMode == EnvelopeV2HintModeRouteHint {
		var hint [8]byte
		binary.BigEndian.PutUint64(hint[:], h.RouteHint)
		out = append(out, hint[:]...)
	}
	out = append(out, sealed...)
	return out, h, nil
}

func ReadEnvelopeV2Prefix(r io.Reader, hintMode EnvelopeV2HintMode) (EnvelopeV2Header, error) {
	var h EnvelopeV2Header
	h.HintMode = hintMode
	if _, err := io.ReadFull(r, h.PrefixRandom[:]); err != nil {
		return h, err
	}
	if hintMode == EnvelopeV2HintModeRouteHint {
		var raw [EnvelopeV2RouteHintSize]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return h, err
		}
		h.RouteHint = binary.BigEndian.Uint64(raw[:])
	} else if hintMode != EnvelopeV2HintModeNone {
		return h, ErrInvalidFrame
	}
	return h, nil
}

func OpenEnvelopeV2Payload(secret []byte, h EnvelopeV2Header, serverPort int, sealed []byte) (EnvelopeV2Payload, error) {
	plain, err := openEnvelopeV2Sealed(secret, h, serverPort, sealed)
	if err != nil {
		return EnvelopeV2Payload{}, err
	}
	payload, next, err := DecodeEnvelopeV2PayloadWithLength(plain)
	if err != nil {
		return EnvelopeV2Payload{}, err
	}
	if next+2 > len(plain) {
		return EnvelopeV2Payload{}, ErrInvalidFrame
	}
	paddingLen := int(binary.BigEndian.Uint16(plain[next : next+2]))
	if next+2+paddingLen != len(plain) {
		return EnvelopeV2Payload{}, ErrInvalidFrame
	}
	if payload.Version != EnvelopeV2Version {
		return EnvelopeV2Payload{}, ErrUnsupportedVersion
	}
	if payload.Flags&^EnvelopeV2FlagServerProof != 0 {
		return EnvelopeV2Payload{}, ErrUnsupportedFlags
	}
	return payload, nil
}

func SealEnvelopeV2Payload(secret []byte, h EnvelopeV2Header, serverPort int, plain []byte) ([]byte, error) {
	return sealEnvelopeV2(secret, h, serverPort, plain)
}

func sealEnvelopeV2(secret []byte, h EnvelopeV2Header, serverPort int, plain []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(deriveEnvelopeV2Key(secret, h.PrefixRandom))
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, envelopeV2Nonce(h.PrefixRandom), plain, envelopeV2AAD(h, serverPort)), nil
}

func openEnvelopeV2Sealed(secret []byte, h EnvelopeV2Header, serverPort int, sealed []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(deriveEnvelopeV2Key(secret, h.PrefixRandom))
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, envelopeV2Nonce(h.PrefixRandom), sealed, envelopeV2AAD(h, serverPort))
}

func ComputeEnvelopeV2RouteHint(secret []byte, prefixRandom [EnvelopeV2PrefixSize]byte, serverPort int) uint64 {
	if serverPort < 0 || serverPort > 65535 {
		return 0
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(serverPort))
	data := append(append([]byte("libknock tcp-auth hint v2"), prefixRandom[:]...), port[:]...)
	return cryptox.HMACTrunc64(secret, data)
}

func BuildEnvelopeV2ServerProof(secret []byte, h EnvelopeV2Header, serverPort int) []byte {
	out := make([]byte, ServerProofSize)
	out[0] = EnvelopeV2Version
	out[1] = ServerProofType
	copy(out[2:18], h.PrefixRandom[:16])
	copy(out[18:], computeEnvelopeV2ServerProof(secret, h, serverPort))
	return out
}

func VerifyEnvelopeV2ServerProof(proof, secret []byte, h EnvelopeV2Header, serverPort int) error {
	if len(proof) != ServerProofSize || proof[0] != EnvelopeV2Version || proof[1] != ServerProofType {
		return ErrInvalidFrame
	}
	if !bytes.Equal(proof[2:18], h.PrefixRandom[:16]) {
		return ErrInvalidFrame
	}
	if !cryptox.ConstantTimeEqual(proof[18:], computeEnvelopeV2ServerProof(secret, h, serverPort)) {
		return ErrInvalidFrame
	}
	return nil
}

func computeEnvelopeV2ServerProof(secret []byte, h EnvelopeV2Header, serverPort int) []byte {
	if serverPort < 0 || serverPort > 65535 {
		return nil
	}
	data := append([]byte("server-proof-v2"), h.PrefixRandom[:]...)
	var buf [10]byte
	binary.BigEndian.PutUint64(buf[:8], h.RouteHint)
	binary.BigEndian.PutUint16(buf[8:], uint16(serverPort))
	data = append(data, buf[:]...)
	return cryptox.HMACSHA256(secret, data)
}

func EncodeEnvelopeV2Payload(p EnvelopeV2Payload) ([]byte, error) {
	if p.ServerPort < 0 || p.ServerPort > 65535 {
		return nil, fmt.Errorf("server port out of range: %d", p.ServerPort)
	}
	if len(p.Method) > 255 || len(p.SessionID) > 255 || len(p.Extensions) > 65535 {
		return nil, ErrFrameTooLarge
	}
	buf := bytes.NewBuffer(make([]byte, 0, 1+1+8+16+2+1+len(p.Method)+1+len(p.SessionID)+2+len(p.Extensions)))
	buf.WriteByte(p.Version)
	buf.WriteByte(p.Flags)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(p.TimestampUnixMS))
	buf.Write(tmp[:])
	buf.Write(p.ClientIDHash[:])
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(p.ServerPort))
	buf.Write(port[:])
	buf.WriteByte(byte(len(p.Method)))
	buf.WriteString(p.Method)
	buf.WriteByte(byte(len(p.SessionID)))
	buf.Write(p.SessionID)
	var extLen [2]byte
	binary.BigEndian.PutUint16(extLen[:], uint16(len(p.Extensions)))
	buf.Write(extLen[:])
	buf.Write(p.Extensions)
	return buf.Bytes(), nil
}

func DecodeEnvelopeV2Payload(raw []byte) (EnvelopeV2Payload, error) {
	p, next, err := DecodeEnvelopeV2PayloadWithLength(raw)
	if err != nil {
		return EnvelopeV2Payload{}, err
	}
	if next != len(raw) {
		return EnvelopeV2Payload{}, ErrInvalidFrame
	}
	return p, nil
}

func DecodeEnvelopeV2PayloadWithLength(raw []byte) (EnvelopeV2Payload, int, error) {
	r := codec.NewReader(raw, ErrInvalidFrame)
	var p EnvelopeV2Payload
	var err error
	if p.Version, err = r.ReadByte(); err != nil {
		return EnvelopeV2Payload{}, 0, err
	}
	if p.Flags, err = r.ReadByte(); err != nil {
		return EnvelopeV2Payload{}, 0, err
	}
	ts, err := r.ReadUint64()
	if err != nil {
		return EnvelopeV2Payload{}, 0, err
	}
	p.TimestampUnixMS = int64(ts)
	id, err := r.ReadFixed(16)
	if err != nil {
		return EnvelopeV2Payload{}, 0, err
	}
	copy(p.ClientIDHash[:], id)
	port, err := r.ReadUint16()
	if err != nil {
		return EnvelopeV2Payload{}, 0, err
	}
	p.ServerPort = int(port)
	methodLen, err := r.ReadByte()
	if err != nil {
		return EnvelopeV2Payload{}, 0, err
	}
	method, err := r.ReadVarBytes(int(methodLen), false)
	if err != nil {
		return EnvelopeV2Payload{}, 0, err
	}
	p.Method = string(method)
	sessionLen, err := r.ReadByte()
	if err != nil {
		return EnvelopeV2Payload{}, 0, err
	}
	if p.SessionID, err = r.ReadVarBytes(int(sessionLen), true); err != nil {
		return EnvelopeV2Payload{}, 0, err
	}
	extLen, err := r.ReadUint16()
	if err != nil {
		return EnvelopeV2Payload{}, 0, err
	}
	if p.Extensions, err = r.ReadVarBytes(int(extLen), true); err != nil {
		return EnvelopeV2Payload{}, 0, err
	}
	return p, r.Pos(), nil
}

func deriveEnvelopeV2Key(secret []byte, prefixRandom [EnvelopeV2PrefixSize]byte) []byte {
	return cryptox.MustHKDFSHA256(secret, prefixRandom[:], []byte("libknock tcp-auth envelope v2"), chacha20poly1305.KeySize)
}

func envelopeV2Nonce(prefixRandom [EnvelopeV2PrefixSize]byte) []byte {
	return prefixRandom[:chacha20poly1305.NonceSizeX]
}

func envelopeV2AAD(h EnvelopeV2Header, serverPort int) []byte {
	out := make([]byte, 0, EnvelopeV2PrefixSize+EnvelopeV2RouteHintSize+2+2+len(EnvelopeV2ProtocolLabel))
	// AAD binds routing, size, port, and protocol domain.
	out = append(out, h.PrefixRandom[:]...)
	if h.HintMode == EnvelopeV2HintModeRouteHint {
		var hint [8]byte
		binary.BigEndian.PutUint64(hint[:], h.RouteHint)
		out = append(out, hint[:]...)
	}
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], uint16(h.BucketSize))
	out = append(out, tmp[:]...)
	binary.BigEndian.PutUint16(tmp[:], uint16(serverPort))
	out = append(out, tmp[:]...)
	out = append(out, EnvelopeV2ProtocolLabel...)
	return out
}

func EnvelopeV2Buckets(in []int) []int {
	if len(in) == 0 {
		return append([]int(nil), EnvelopeV2DefaultBuckets...)
	}
	out := make([]int, 0, len(in))
	seen := map[int]bool{}
	for _, v := range in {
		if !EnvelopeV2SupportedBucket(v) || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func EnvelopeV2SupportedBucket(bucket int) bool {
	for _, candidate := range EnvelopeV2DefaultBuckets {
		if bucket == candidate {
			return true
		}
	}
	return false
}

func randInt(max int) (int, error) {
	if max <= 0 {
		return 0, ErrInvalidFrame
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}
