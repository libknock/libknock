package netx

import (
	"errors"
	"net"
)

var ErrAuthBackpressure = errors.New("auth pending queue full")

// ErrAuthSourceLimit reports a connection dropped because its source already
// holds MaxPendingAuthPerSource pending or in-progress authentications.
var ErrAuthSourceLimit = errors.New("auth per-source pending limit reached")

type EventSink interface {
	OnAuthDrop(remote net.Addr, reason error, pending int)
}
