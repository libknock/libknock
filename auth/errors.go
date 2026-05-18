package auth

import "errors"

var (
	ErrNilConn               = errors.New("nil connection")
	ErrInvalidFrame          = errors.New("invalid frame")
	ErrFrameTooLarge         = errors.New("frame too large")
	ErrUnknownClient         = errors.New("unknown client")
	ErrAuthFailed            = errors.New("auth failed")
	ErrReplayDetected        = errors.New("replay detected")
	ErrTimeSkew              = errors.New("timestamp outside allowed window")
	ErrKnockRequired         = errors.New("knock session required")
	ErrUnsupportedVersion    = errors.New("unsupported protocol version")
	ErrInvalidClientID       = errors.New("invalid client id")
	ErrInvalidSecret         = errors.New("secret must be at least 16 bytes")
	ErrMissingSecretResolver = errors.New("missing secret resolver")
	ErrMissingReplayCache    = errors.New("missing replay cache")
	ErrRateLimited           = errors.New("rate limited")
	ErrServerProofRequired   = errors.New("server proof required")
	ErrServerProofFailed     = errors.New("server proof verification failed")
	ErrUnsupportedFlags      = errors.New("unsupported flags")
	ErrSecretResolverFailed  = errors.New("secret resolver failed")
	ErrTooManyCandidates     = errors.New("too many auth candidates")
)
