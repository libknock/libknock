package observability

import (
	"net/netip"
	"testing"
	"time"
)

func TestNopImplementsEventSink(t *testing.T) {
	var _ EventSink = Nop{}
	Nop{}.OnKnockOK(KnockEvent{Remote: netip.MustParseAddr("127.0.0.1"), ClientID: "client", Method: "udp", Parts: 1, TTL: time.Second})
}
