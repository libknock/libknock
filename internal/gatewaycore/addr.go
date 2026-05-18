package gatewaycore

import (
	"net"
	"net/netip"
	"strconv"
)

func ListenerPort(addr net.Addr) int {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.Port
	}
	return 0
}

func ListenerPortFromString(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(p)
	return port
}

func UDPListenForKnockPort(addr net.Addr, knockPort int) string {
	if knockPort <= 0 {
		return addr.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(knockPort))
}

func UDPListenStringForKnockPort(addr string, knockPort int) string {
	if knockPort <= 0 {
		return addr
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return net.JoinHostPort(host, strconv.Itoa(knockPort))
}

func AddrFromNet(addr net.Addr) (netip.Addr, bool) {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		a, ok := netip.AddrFromSlice(tcp.IP)
		if ok {
			a = a.Unmap()
		}
		return a, ok
	}
	if addr == nil {
		return netip.Addr{}, false
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(host)
	return a, err == nil
}
