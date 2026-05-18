package protocol

import (
	"testing"
	"time"
)

var benchSecret = []byte("0123456789abcdef0123456789abcdef")

func BenchmarkProtocolFrameEncodeDecode(b *testing.B) {
	frame, h, err := BuildFrame("client", benchSecret, 443, time.Unix(1700000000, 0), FlagServerProof, "tcp-auth", []byte("session-id-0001!"), []byte{1, 2, 3})
	if err != nil {
		b.Fatal(err)
	}
	sealed := frame[HeaderSize:]
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		plain, err := OpenPayload(benchSecret, h, sealed)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := DecodePayload(plain); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEnvelopeV2SealOpen(b *testing.B) {
	frame, h, err := BuildEnvelopeV2("client", benchSecret, 443, time.Unix(1700000000, 0), FlagServerProof, "tcp-auth", []byte("session-id-0001!"), []byte{1, 2, 3}, EnvelopeV2Config{})
	if err != nil {
		b.Fatal(err)
	}
	sealed := frame[EnvelopeV2PrefixSize+EnvelopeV2RouteHintSize:]
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := OpenEnvelopeV2Payload(benchSecret, h, 443, sealed); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEnvelopeV2OpenWithRouteHint(b *testing.B) { BenchmarkEnvelopeV2SealOpen(b) }

func BenchmarkEnvelopeV2OpenWithHintNoneManyCandidates(b *testing.B) {
	cfg := EnvelopeV2Config{HintMode: EnvelopeV2HintModeNone}
	frame, h, err := BuildEnvelopeV2("client", benchSecret, 443, time.Unix(1700000000, 0), 0, "tcp-auth", nil, nil, cfg)
	if err != nil {
		b.Fatal(err)
	}
	sealed := frame[EnvelopeV2PrefixSize:]
	candidates := make([][]byte, 32)
	for i := range candidates {
		candidates[i] = []byte("0123456789abcdef0123456789abcdee")
	}
	candidates[len(candidates)-1] = benchSecret
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, secret := range candidates {
			if _, err := OpenEnvelopeV2Payload(secret, h, 443, sealed); err == nil {
				break
			}
		}
	}
}
