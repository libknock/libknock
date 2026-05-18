package cryptox

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

func HMACSHA256(secret, data []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func HMACTrunc64(secret, data []byte) uint64 {
	return binary.BigEndian.Uint64(HMACSHA256(secret, data)[:8])
}

func HMACTrunc128(secret, data []byte) [16]byte {
	var out [16]byte
	copy(out[:], HMACSHA256(secret, data)[:16])
	return out
}
