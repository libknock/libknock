package auth

import (
	"net"
	"strconv"
)

func effectivePort(configured int, addr net.Addr) int {
	if configured > 0 {
		return configured
	}
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.Port
	}
	if addr == nil {
		return 0
	}
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return 0
	}
	return n
}
