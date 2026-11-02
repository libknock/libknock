// Package listenx creates the TCP listeners that libknock gateways own.
//
// Since Go 1.24, net.Listen and net.ListenConfig accept Multipath TCP (MPTCP)
// by default on Linux (GODEBUG multipathtcp=2). An MPTCP connection can gain
// extra subflows from other source addresses through MP_JOIN, and those
// subflows never pass through Accept. libknock binds authentication, knock
// sessions, policy, bans and per-source limits to the address of the first
// subflow, so a joined subflow from another address would bypass all of them.
// Gateway listeners therefore disable MPTCP unless the caller opts in.
package listenx

import (
	"context"
	"net"
)

// ListenTCP listens on addr with MPTCP explicitly enabled or disabled,
// independent of the Go version and GODEBUG default.
func ListenTCP(ctx context.Context, addr string, mptcp bool) (net.Listener, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var lc net.ListenConfig
	lc.SetMultipathTCP(mptcp)
	return lc.Listen(ctx, "tcp", addr)
}
