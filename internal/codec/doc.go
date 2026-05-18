// Package codec contains narrow binary parsing and writing helpers for libknock
// wire formats.
//
// The helpers centralize offset checks and TLV framing used by protocol and
// knock packages without exposing a general-purpose serialization API.
package codec
