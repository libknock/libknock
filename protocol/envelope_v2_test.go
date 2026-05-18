package protocol

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestEnvelopeV2RoundTripAndBucketSize(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	frame, h, err := BuildEnvelopeV2("client", secret, 443, time.Now(), FlagServerProof, "udp-seq", []byte("session-1"), []byte{1, 2, 3}, EnvelopeV2Config{})
	if err != nil {
		t.Fatal(err)
	}
	if h.BucketSize != len(frame) || !bucketIn(h.BucketSize, EnvelopeV2DefaultBuckets) {
		t.Fatalf("bucket=%d len=%d, want configured bucket", h.BucketSize, len(frame))
	}
	br := bytes.NewReader(frame)
	gotHeader, err := ReadEnvelopeV2Prefix(br, EnvelopeV2HintModeRouteHint)
	if err != nil {
		t.Fatal(err)
	}
	gotHeader.BucketSize = len(frame)
	sealed := make([]byte, br.Len())
	_, _ = br.Read(sealed)
	payload, err := OpenEnvelopeV2Payload(secret, gotHeader, 443, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Version != EnvelopeV2Version || payload.Flags != FlagServerProof || payload.Method != "udp-seq" || string(payload.SessionID) != "session-1" || !bytes.Equal(payload.Extensions, []byte{1, 2, 3}) {
		t.Fatalf("payload = %+v", payload)
	}
}

func bucketIn(bucket int, buckets []int) bool {
	for _, candidate := range buckets {
		if bucket == candidate {
			return true
		}
	}
	return false
}

func TestEnvelopeV2PrefixDoesNotCollideWithFrameV1Version(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	for i := 0; i < 1024; i++ {
		_, h, err := BuildEnvelopeV2("client", secret, 443, time.Now(), 0, "", nil, nil, EnvelopeV2Config{})
		if err != nil {
			t.Fatal(err)
		}
		if h.PrefixRandom[0] == Version {
			t.Fatalf("envelope v2 prefix first byte collided with frame v1 version: 0x%02x", h.PrefixRandom[0])
		}
	}
}

func TestEnvelopeV2RejectsWrongSecretAndHint(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	frame, h, err := BuildEnvelopeV2("client", secret, 443, time.Now(), 0, "", nil, nil, EnvelopeV2Config{})
	if err != nil {
		t.Fatal(err)
	}
	h.BucketSize = len(frame)
	sealed := frame[EnvelopeV2PrefixSize+EnvelopeV2RouteHintSize:]
	if _, err := OpenEnvelopeV2Payload([]byte("abcdef0123456789abcdef0123456789"), h, 443, sealed); err == nil {
		t.Fatal("wrong secret opened envelope")
	}
	if got := ComputeEnvelopeV2RouteHint([]byte("abcdef0123456789abcdef0123456789"), h.PrefixRandom, 443); got == h.RouteHint {
		t.Fatal("wrong secret produced same route hint")
	}
}

func TestEnvelopeV2RejectsUnsupportedFlags(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	if _, _, err := BuildEnvelopeV2("client", secret, 443, time.Now(), 0x80, "", nil, nil, EnvelopeV2Config{}); !errors.Is(err, ErrUnsupportedFlags) {
		t.Fatalf("BuildEnvelopeV2 err = %v, want unsupported flags", err)
	}
}

func TestEnvelopeV2RejectsPayloadLengthMismatch(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	frame, h, err := BuildEnvelopeV2("client", secret, 443, time.Now(), 0, "udp", nil, nil, EnvelopeV2Config{})
	if err != nil {
		t.Fatal(err)
	}
	h.BucketSize = len(frame)
	sealed := append([]byte(nil), frame[EnvelopeV2PrefixSize+EnvelopeV2RouteHintSize:]...)
	sealed[len(sealed)-1] ^= 1
	if _, err := OpenEnvelopeV2Payload(secret, h, 443, sealed); err == nil {
		t.Fatal("tampered envelope opened")
	}
}

func TestEnvelopeV2RejectsUnsupportedBuckets(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	if _, _, err := BuildEnvelopeV2("client", secret, 443, time.Now(), 0, "udp", nil, nil, EnvelopeV2Config{FrameSizeBuckets: []int{1024}}); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("BuildEnvelopeV2 err = %v, want frame too large", err)
	}
	if buckets := EnvelopeV2Buckets([]int{127, 128, 160, 192, 1024}); len(buckets) != 2 || buckets[0] != 128 || buckets[1] != 192 {
		t.Fatalf("buckets = %v, want [128 192]", buckets)
	}
}
