package gatewaycore

import "time"

func DefaultString(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}

// DefaultKnockReplayTTL is the minimum lifetime of knock replay-cache entries.
const DefaultKnockReplayTTL = 5 * time.Minute

// KnockReplayTTL returns a replay-cache TTL that always covers the full
// acceptance window of a knock frame. A frame is accepted while its timestamp
// is within +/- window of the server clock, so a nonce must be remembered for
// at least 2*window; otherwise a captured knock can be replayed after its
// replay entry expires but while its timestamp is still accepted.
func KnockReplayTTL(window time.Duration) time.Duration {
	if window <= 0 {
		window = 30 * time.Second
	}
	ttl := 2*window + time.Second
	if ttl < DefaultKnockReplayTTL {
		return DefaultKnockReplayTTL
	}
	return ttl
}
