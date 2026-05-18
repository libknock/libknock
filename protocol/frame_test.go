package protocol

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestHeaderCarriesWireVersion(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	frame, header, err := BuildFrame("client", secret, 443, time.Now(), FlagServerProof, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if header.Version != Version || frame[0] != Version {
		t.Fatalf("version header = %d frame[0] = %d", header.Version, frame[0])
	}
	frame[0] = Version + 1
	if _, _, err := ReadFrame(bytes.NewReader(frame), DefaultMaxFrameSize); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("ReadFrame err = %v, want unsupported version", err)
	}
}

func TestHeaderHelpersTolerateShortBuffers(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("header helper panicked on short buffer: %v", r)
		}
	}()
	EncodeHeader(make([]byte, HeaderSize-1), Header{Version: Version})
	if got := DecodeHeader(make([]byte, HeaderSize-1)); got != (Header{}) {
		t.Fatalf("DecodeHeader short buffer = %+v, want zero header", got)
	}
}

func TestBuildFrameRejectsPortOverflow(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	if _, _, err := BuildFrame("client", secret, 65536, time.Now(), 0, "", nil, nil); err == nil {
		t.Fatal("BuildFrame accepted overflowing port")
	}
	if _, _, err := BuildFrame("client", secret, -1, time.Now(), 0, "", nil, nil); err == nil {
		t.Fatal("BuildFrame accepted negative port")
	}
}

func TestAEADKeyIsFrameBound(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	h1 := Header{Nonce: [16]byte{1}, KeyHint: 1}
	h2 := Header{Nonce: [16]byte{2}, KeyHint: 1}
	sealed, err := SealPayload(secret, h1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPayload(secret, h1, sealed); err != nil {
		t.Fatalf("OpenPayload same header: %v", err)
	}
	if _, err := OpenPayload(secret, h2, sealed); err == nil {
		t.Fatal("OpenPayload with different frame header succeeded")
	}
}

func TestReadFrameRejectsUnsupportedFlags(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	frame, _, err := BuildFrame("client", secret, 443, time.Now(), FlagServerProof, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	frame[1] |= 0x80
	if _, _, err := ReadFrame(bytes.NewReader(frame), DefaultMaxFrameSize); !errors.Is(err, ErrUnsupportedFlags) {
		t.Fatalf("ReadFrame err = %v, want unsupported flags", err)
	}
}

func TestBuildFrameRejectsUnsupportedFlags(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	if _, _, err := BuildFrame("client", secret, 443, time.Now(), FlagServerProof|0x80, "", nil, nil); !errors.Is(err, ErrUnsupportedFlags) {
		t.Fatalf("BuildFrame err = %v, want unsupported flags", err)
	}
}

func TestDecodePayloadRejectsTrailingAndLengthMismatch(t *testing.T) {
	var hash [16]byte
	copy(hash[:], []byte("0123456789abcdef"))
	payload, err := EncodePayload(Payload{ClientIDHash: hash, TimestampUnixMS: time.Now().UnixMilli(), ServerPort: 443, Method: "udp", SessionID: []byte("session"), Extensions: []byte{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePayload(append(append([]byte(nil), payload...), 0)); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("DecodePayload trailing err = %v, want invalid frame", err)
	}
	badMethodLen := append([]byte(nil), payload...)
	badMethodLen[26] = 200
	if _, err := DecodePayload(badMethodLen); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("DecodePayload bad method len err = %v, want invalid frame", err)
	}
	badExtLen := append([]byte(nil), payload...)
	badExtLen[len(badExtLen)-3] = 0
	badExtLen[len(badExtLen)-2] = 3
	if _, err := DecodePayload(badExtLen); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("DecodePayload bad ext len err = %v, want invalid frame", err)
	}
}
