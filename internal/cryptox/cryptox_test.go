package cryptox

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHKDFSHA256RFC5869SHA256Vector(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := mustHex(t, "000102030405060708090a0b0c")
	info := mustHex(t, "f0f1f2f3f4f5f6f7f8f9")
	want := mustHex(t, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
	got, err := HKDFSHA256(ikm, salt, info, len(want))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("HKDFSHA256 = %x, want %x", got, want)
	}
	if got := MustHKDFSHA256(ikm, salt, info, len(want)); !bytes.Equal(got, want) {
		t.Fatalf("MustHKDFSHA256 = %x, want %x", got, want)
	}
}

func TestHMACTruncationStableOutput(t *testing.T) {
	if got, want := HMACTrunc64([]byte("key"), []byte("data")), uint64(0x5031fe3d989c6d15); got != want {
		t.Fatalf("HMACTrunc64 = %#x, want %#x", got, want)
	}
	want128 := [16]byte{0x50, 0x31, 0xfe, 0x3d, 0x98, 0x9c, 0x6d, 0x15, 0x37, 0xa0, 0x13, 0xfa, 0x6e, 0x73, 0x9d, 0xa2}
	if got := HMACTrunc128([]byte("key"), []byte("data")); got != want128 {
		t.Fatalf("HMACTrunc128 = %x, want %x", got, want128)
	}
}

func TestConstantTimeEqualMatchesByteEquality(t *testing.T) {
	cases := []struct {
		a, b []byte
		want bool
	}{
		{[]byte("same"), []byte("same"), true},
		{[]byte("same"), []byte("diff"), false},
		{[]byte("same"), []byte("same\x00"), false},
		{nil, nil, true},
	}
	for _, tc := range cases {
		if got := ConstantTimeEqual(tc.a, tc.b); got != tc.want || got != bytes.Equal(tc.a, tc.b) {
			t.Fatalf("ConstantTimeEqual(%x, %x) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
