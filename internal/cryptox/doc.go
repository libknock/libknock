// Package cryptox centralizes small cryptographic primitives used by protocol
// code.
//
// It keeps HKDF, HMAC truncation, and constant-time comparison behavior in one
// auditable place while avoiding a public crypto abstraction that callers could
// mistake for an extension point. Panic-shaped helpers such as MustHKDFSHA256
// are reserved for internal invariants where HKDF over SHA-256 should not
// return runtime I/O errors; new external-facing code should prefer explicit
// error-returning helpers.
package cryptox
