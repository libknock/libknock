package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/libknock/libknock/internal/codec"
	"github.com/libknock/libknock/internal/cryptox"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Version             = byte(1)
	FlagServerProof     = byte(1 << 0)
	ServerProofType     = byte(0x50)
	ServerProofSize     = 1 + 1 + 16 + 32
	HeaderSize          = 1 + 1 + 1 + 16 + 8 + 2
	DefaultMaxFrameSize = 1024
	MinSecretSize       = 16
)

var (
	ErrInvalidFrame       = errors.New("invalid frame")
	ErrFrameTooLarge      = errors.New("frame too large")
	ErrUnsupportedVersion = errors.New("unsupported protocol version")
	ErrUnsupportedFlags   = errors.New("unsupported flags")
)

type Header struct {
	Version   byte
	Flags     byte
	Reserved  byte
	Nonce     [16]byte
	KeyHint   uint64
	SealedLen uint16
}

type Payload struct {
	ClientIDHash    [16]byte
	TimestampUnixMS int64
	ServerPort      int
	Method          string
	SessionID       []byte
	Extensions      []byte
}

type TLV struct {
	Type  uint16
	Value []byte
}

func BuildFrame(clientID string, secret []byte, serverPort int, now time.Time, flags byte, method string, sessionID, extensions []byte) ([]byte, Header, error) {
	if clientID == "" || len(secret) < MinSecretSize {
		return nil, Header{}, ErrInvalidFrame
	}
	if flags&^FlagServerProof != 0 {
		return nil, Header{}, ErrUnsupportedFlags
	}
	h := Header{Version: Version, Flags: flags}
	if _, err := rand.Read(h.Nonce[:]); err != nil {
		return nil, Header{}, err
	}
	if serverPort < 0 || serverPort > 65535 {
		return nil, Header{}, fmt.Errorf("server port out of range: %d", serverPort)
	}
	h.KeyHint = ComputeKeyHint(secret, h.Nonce, serverPort)
	plain, err := EncodePayload(Payload{ClientIDHash: ComputeClientIDHash(secret, clientID), TimestampUnixMS: now.UnixMilli(), ServerPort: serverPort, Method: method, SessionID: sessionID, Extensions: extensions})
	if err != nil {
		return nil, Header{}, err
	}
	sealedLen := len(plain) + chacha20poly1305.Overhead
	if sealedLen > DefaultMaxFrameSize-HeaderSize {
		return nil, Header{}, ErrFrameTooLarge
	}
	h.SealedLen = uint16(sealedLen)
	sealed, err := SealPayload(secret, h, plain)
	if err != nil {
		return nil, Header{}, err
	}
	out := make([]byte, HeaderSize+len(sealed))
	EncodeHeader(out[:HeaderSize], h)
	copy(out[HeaderSize:], sealed)
	return out, h, nil
}

func ReadFrame(r io.Reader, maxFrameSize int) (Header, []byte, error) {
	if maxFrameSize <= 0 {
		maxFrameSize = DefaultMaxFrameSize
	}
	if maxFrameSize < HeaderSize {
		return Header{}, nil, ErrFrameTooLarge
	}
	var raw [HeaderSize]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return Header{}, nil, err
	}
	h := DecodeHeader(raw[:])
	if h.Version != Version {
		return Header{}, nil, ErrUnsupportedVersion
	}
	if h.Reserved != 0 {
		return Header{}, nil, ErrInvalidFrame
	}
	if h.Flags&^FlagServerProof != 0 {
		return Header{}, nil, ErrUnsupportedFlags
	}
	if h.SealedLen == 0 || HeaderSize+int(h.SealedLen) > maxFrameSize {
		return Header{}, nil, ErrFrameTooLarge
	}
	sealed := make([]byte, h.SealedLen)
	if _, err := io.ReadFull(r, sealed); err != nil {
		return Header{}, nil, err
	}
	return h, sealed, nil
}

func EncodeHeader(dst []byte, h Header) {
	if len(dst) < HeaderSize {
		return
	}
	dst[0] = h.Version
	dst[1] = h.Flags
	dst[2] = h.Reserved
	copy(dst[3:19], h.Nonce[:])
	binary.BigEndian.PutUint64(dst[19:27], h.KeyHint)
	binary.BigEndian.PutUint16(dst[27:29], h.SealedLen)
}

func DecodeHeader(src []byte) Header {
	var h Header
	if len(src) < HeaderSize {
		return h
	}
	h.Version = src[0]
	h.Flags = src[1]
	h.Reserved = src[2]
	copy(h.Nonce[:], src[3:19])
	h.KeyHint = binary.BigEndian.Uint64(src[19:27])
	h.SealedLen = binary.BigEndian.Uint16(src[27:29])
	return h
}

func SealPayload(secret []byte, h Header, plain []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(deriveAEADKey(secret, h))
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, aeadNonce(h), plain, aad(h)), nil
}

func OpenPayload(secret []byte, h Header, sealed []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(deriveAEADKey(secret, h))
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, aeadNonce(h), sealed, aad(h))
}

func ComputeKeyHint(secret []byte, nonce [16]byte, serverPort int) uint64 {
	if serverPort < 0 || serverPort > 65535 {
		return 0
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(serverPort))
	data := append(append([]byte("hint"), nonce[:]...), port[:]...)
	return cryptox.HMACTrunc64(secret, data)
}

func ComputeClientIDHash(secret []byte, clientID string) [16]byte {
	return cryptox.HMACTrunc128(secret, append([]byte("client-id"), clientID...))
}

func BuildServerProof(secret []byte, h Header, serverPort int) []byte {
	out := make([]byte, ServerProofSize)
	out[0] = Version
	out[1] = ServerProofType
	copy(out[2:18], h.Nonce[:])
	copy(out[18:], computeServerProof(secret, h, serverPort))
	return out
}

func VerifyServerProof(proof, secret []byte, h Header, serverPort int) error {
	if len(proof) != ServerProofSize || proof[0] != Version || proof[1] != ServerProofType {
		return ErrInvalidFrame
	}
	if !bytes.Equal(proof[2:18], h.Nonce[:]) {
		return ErrInvalidFrame
	}
	if !cryptox.ConstantTimeEqual(proof[18:], computeServerProof(secret, h, serverPort)) {
		return ErrInvalidFrame
	}
	return nil
}

func computeServerProof(secret []byte, h Header, serverPort int) []byte {
	if serverPort < 0 || serverPort > 65535 {
		return nil
	}
	data := append([]byte("server-proof-v1"), h.Nonce[:]...)
	var buf [10]byte
	binary.BigEndian.PutUint64(buf[:8], h.KeyHint)
	binary.BigEndian.PutUint16(buf[8:], uint16(serverPort))
	data = append(data, buf[:]...)
	return cryptox.HMACSHA256(secret, data)
}

func EncodePayload(p Payload) ([]byte, error) {
	if p.ServerPort < 0 || p.ServerPort > 65535 {
		return nil, fmt.Errorf("server port out of range: %d", p.ServerPort)
	}
	if len(p.Method) > 255 || len(p.SessionID) > 255 || len(p.Extensions) > 65535 {
		return nil, ErrFrameTooLarge
	}
	buf := bytes.NewBuffer(make([]byte, 0, 16+8+2+1+len(p.Method)+1+len(p.SessionID)+2+len(p.Extensions)))
	buf.Write(p.ClientIDHash[:])
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(p.TimestampUnixMS))
	buf.Write(tmp[:])
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

func DecodePayload(raw []byte) (Payload, error) {
	r := codec.NewReader(raw, ErrInvalidFrame)
	var p Payload
	id, err := r.ReadFixed(16)
	if err != nil {
		return Payload{}, err
	}
	copy(p.ClientIDHash[:], id)
	ts, err := r.ReadUint64()
	if err != nil {
		return Payload{}, err
	}
	p.TimestampUnixMS = int64(ts)
	port, err := r.ReadUint16()
	if err != nil {
		return Payload{}, err
	}
	p.ServerPort = int(port)
	methodLen, err := r.ReadByte()
	if err != nil {
		return Payload{}, err
	}
	method, err := r.ReadVarBytes(int(methodLen), false)
	if err != nil {
		return Payload{}, err
	}
	p.Method = string(method)
	sessionLen, err := r.ReadByte()
	if err != nil {
		return Payload{}, err
	}
	if p.SessionID, err = r.ReadVarBytes(int(sessionLen), true); err != nil {
		return Payload{}, err
	}
	extLen, err := r.ReadUint16()
	if err != nil {
		return Payload{}, err
	}
	if int(extLen) != r.Remaining() {
		return Payload{}, ErrInvalidFrame
	}
	p.Extensions, err = r.ReadVarBytes(int(extLen), true)
	if err != nil {
		return Payload{}, err
	}
	return p, nil
}

func EncodeTLVs(tlvs []TLV) ([]byte, error) {
	inner := make([]codec.TLV, len(tlvs))
	for i, tlv := range tlvs {
		inner[i] = codec.TLV{Type: tlv.Type, Value: tlv.Value}
	}
	return codec.EncodeTLVs(inner, ErrFrameTooLarge)
}

func DecodeTLVs(raw []byte) ([]TLV, error) {
	inner, err := codec.DecodeTLVs(raw, ErrInvalidFrame)
	if err != nil {
		return nil, err
	}
	out := make([]TLV, len(inner))
	for i, tlv := range inner {
		out[i] = TLV{Type: tlv.Type, Value: tlv.Value}
	}
	return out, nil
}

func deriveAEADKey(secret []byte, h Header) []byte {
	info := make([]byte, 0, len("libknock aead v1")+8)
	info = append(info, "libknock aead v1"...)
	var hint [8]byte
	binary.BigEndian.PutUint64(hint[:], h.KeyHint)
	info = append(info, hint[:]...)
	return cryptox.MustHKDFSHA256(secret, h.Nonce[:], info, chacha20poly1305.KeySize)
}

func aeadNonce(h Header) []byte {
	var nonce [chacha20poly1305.NonceSizeX]byte
	copy(nonce[0:16], h.Nonce[:])
	binary.BigEndian.PutUint64(nonce[16:24], h.KeyHint)
	return nonce[:]
}

func aad(h Header) []byte {
	out := make([]byte, HeaderSize)
	EncodeHeader(out, h)
	return out
}
