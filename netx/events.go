package netx

import (
	"errors"
	"net"
)

var ErrAuthBackpressure = errors.New("auth pending queue full")

type EventSink interface {
	OnAuthDrop(remote net.Addr, reason error, pending int)
}
