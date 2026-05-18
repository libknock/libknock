package cryptox

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

func HKDFSHA256(secret, salt, info []byte, n int) ([]byte, error) {
	key := make([]byte, n)
	_, err := io.ReadFull(hkdf.New(sha256.New, secret, salt, info), key)
	return key, err
}

func MustHKDFSHA256(secret, salt, info []byte, n int) []byte {
	key, err := HKDFSHA256(secret, salt, info, n)
	if err != nil {
		// hkdf.Reader over SHA-256 is deterministic and does not return runtime I/O errors; panic only if that invariant changes.
		panic(err)
	}
	return key
}
