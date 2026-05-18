// Package cryptox centralizes small cryptographic primitives used by protocol
// code.
//
// It keeps HKDF, HMAC truncation, and constant-time comparison behavior in one
// auditable place while avoiding a public crypto abstraction that callers could
// mistake for an extension point.
package cryptox
