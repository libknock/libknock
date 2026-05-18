package protocol

import (
	"bytes"
	"testing"
	"time"
)

func FuzzDecodePayload(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3})
	f.Add(bytes.Repeat([]byte{0}, 29))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodePayload(data)
	})
}

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{Version, 0, 0})
	f.Add(bytes.Repeat([]byte{0xff}, HeaderSize+4))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ReadFrame(bytes.NewReader(data), DefaultMaxFrameSize)
	})
}

func FuzzEnvelopeV2Open(f *testing.F) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	frame, h, err := BuildEnvelopeV2("client", secret, 443, timeNowForFuzz(), 0, "tcp-auth", nil, nil, EnvelopeV2Config{})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(frame[EnvelopeV2PrefixSize+EnvelopeV2RouteHintSize:])
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, EnvelopeV2DefaultMaxSize))
	f.Fuzz(func(t *testing.T, sealed []byte) { _, _ = OpenEnvelopeV2Payload(secret, h, 443, sealed) })
}

func timeNowForFuzz() time.Time { return time.Unix(1700000000, 0) }
