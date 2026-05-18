// Package cache provides small TTL/LRU primitives for internal state stores.
//
// It is shared by replay, ban, and session-oriented code where eviction policy
// is an implementation detail. Public packages keep their domain-specific APIs
// so callers do not depend on cache layout or cleanup mechanics.
package cache
