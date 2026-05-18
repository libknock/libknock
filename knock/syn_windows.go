//go:build windows

package knock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

func Send(ctx context.Context, opts SendOptions) error {
	if err := ValidateSendOptions(opts); err != nil {
		return err
	}
	if opts.TimeWindow <= 0 {
		opts.TimeWindow = 30 * time.Second
	}
	remote, err := net.ResolveTCPAddr("tcp4", opts.ServerAddr)
	if err != nil {
		return err
	}
	if remote.IP == nil {
		return fmt.Errorf("server address %q did not resolve to an IP address", opts.ServerAddr)
	}
	if remote.IP.To4() == nil {
		return errors.New("windows tcp-syn knock via Npcap currently supports IPv4 only; use udp/udp-passive for IPv6")
	}
	localIP, err := outboundIPv4(remote)
	if err != nil {
		return err
	}
	fields := ComputeSYNFields(opts.Secret, opts.ClientID, opts.ServerPort, SlotFor(time.Now(), opts.TimeWindow))
	srcPort, err := randomEphemeralPort()
	if err != nil {
		return err
	}
	ipPacket, err := buildSYNPacket(localIP, remote.IP.To4(), srcPort, opts.ServerPort, fields)
	if err != nil {
		return err
	}
	if err := windowsSendIPPacketWinDivert(ipPacket); err == nil {
		return nil
	}
	iface, err := windowsRouteInterface(localIP)
	if err != nil {
		return err
	}
	gatewayIP, err := windowsGatewayIPv4(remote.IP.To4(), iface, localIP)
	if err != nil {
		return err
	}
	dstMAC, err := windowsResolveMAC(ctx, iface, gatewayIP)
	if err != nil {
		return err
	}
	adapterNames, err := windowsAdapterNameCandidates(iface)
	if err != nil {
		return err
	}
	return windowsSendFrame(adapterNames, buildEthernetIPv4Frame(iface.HardwareAddr, dstMAC, ipPacket))
}

func SendSYNSequence(ctx context.Context, opts SendOptions) error {
	if err := ValidateSendOptions(opts); err != nil {
		return err
	}
	seq := normalizedSequenceOptions(opts.Sequence)
	remote, err := net.ResolveTCPAddr("tcp4", opts.ServerAddr)
	if err != nil {
		return err
	}
	if remote.IP == nil {
		return fmt.Errorf("server address %q did not resolve to an IP address", opts.ServerAddr)
	}
	if remote.IP.To4() == nil {
		return errors.New("windows tcp-syn-seq knock currently supports IPv4 only; use udp/udp-seq for IPv6")
	}
	localIP, err := outboundIPv4(remote)
	if err != nil {
		return err
	}
	parts := ComputeSYNSeqParts(opts.Secret, opts.ClientID, opts.ServerPort, time.Now().Unix()/int64(seq.SlotSeconds), seq.Length)
	if err := windowsSendSYNSequenceWinDivert(ctx, localIP, remote.IP.To4(), parts, seq); err == nil {
		return nil
	}
	iface, err := windowsRouteInterface(localIP)
	if err != nil {
		return err
	}
	gatewayIP, err := windowsGatewayIPv4(remote.IP.To4(), iface, localIP)
	if err != nil {
		return err
	}
	dstMAC, err := windowsResolveMAC(ctx, iface, gatewayIP)
	if err != nil {
		return err
	}
	adapterNames, err := windowsAdapterNameCandidates(iface)
	if err != nil {
		return err
	}
	for i, part := range parts {
		srcPort, err := randomEphemeralPort()
		if err != nil {
			return err
		}
		packet, err := buildSYNPacket(localIP, remote.IP.To4(), srcPort, part.Port, part.Fields)
		if err != nil {
			return err
		}
		if err := windowsSendFrame(adapterNames, buildEthernetIPv4Frame(iface.HardwareAddr, dstMAC, packet)); err != nil {
			return err
		}
		if err := sleepSequenceInterval(ctx, i, len(parts), seq); err != nil {
			return err
		}
	}
	return nil
}

func windowsSendSYNSequenceWinDivert(ctx context.Context, localIP, remoteIP net.IP, parts []SYNSeqPart, seq SequenceOptions) error {
	for i, part := range parts {
		srcPort, err := randomEphemeralPort()
		if err != nil {
			return err
		}
		packet, err := buildSYNPacket(localIP, remoteIP, srcPort, part.Port, part.Fields)
		if err != nil {
			return err
		}
		if err := windowsSendIPPacketWinDivert(packet); err != nil {
			return err
		}
		if err := sleepSequenceInterval(ctx, i, len(parts), seq); err != nil {
			return err
		}
	}
	return nil
}

func Listen(ctx context.Context, opts ListenOptions, handler Handler) error { return ErrUnsupported }
func ListenSYNSequence(ctx context.Context, opts ListenOptions, handler Handler) error {
	return ErrUnsupported
}
func ListenUDPPassive(ctx context.Context, opts ListenOptions, handler Handler) error {
	return ErrUnsupported
}
func ListenUDPPassiveSequence(ctx context.Context, opts ListenOptions, handler Handler) error {
	return ErrUnsupported
}
func CheckServerPrivileges() error {
	return errors.New("server requires Linux CAP_NET_ADMIN and CAP_NET_RAW, or must be run as root")
}

func windowsRouteInterface(localIP net.IP) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifaces {
		iface := &ifaces[i]
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) != 6 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip, _, ok := strings.Cut(a.String(), "/")
			if !ok {
				continue
			}
			if net.ParseIP(ip).To4().Equal(localIP.To4()) {
				return iface, nil
			}
		}
	}
	return nil, fmt.Errorf("could not find outbound interface for local IPv4 %s", localIP)
}

func windowsGatewayIPv4(remoteIP net.IP, iface *net.Interface, localIP net.IP) (net.IP, error) {
	if sameIPv4Subnet(remoteIP, iface, localIP) {
		return remoteIP.To4(), nil
	}
	rows, err := windowsIPv4Routes()
	if err != nil {
		return nil, err
	}
	bestPrefix := -1
	var best net.IP
	var bestSource string
	for _, r := range rows {
		if r.ifIndex != iface.Index || !r.contains(remoteIP.To4()) {
			continue
		}
		if r.prefixLen > bestPrefix {
			bestPrefix = r.prefixLen
			best = r.gateway
			bestSource = r.source
		}
	}
	if bestPrefix < 0 || best == nil {
		return nil, fmt.Errorf("could not determine IPv4 gateway for %s on interface %s after loading %d routes", remoteIP, iface.Name, len(rows))
	}
	if best.Equal(net.IPv4zero) {
		return remoteIP.To4(), nil
	}
	_ = bestSource
	return best.To4(), nil
}

func sameIPv4Subnet(remoteIP net.IP, iface *net.Interface, localIP net.IP) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || !ipNet.IP.To4().Equal(localIP.To4()) {
			continue
		}
		return ipNet.Contains(remoteIP.To4())
	}
	return false
}

func windowsAdapterNameCandidates(iface *net.Interface) ([]string, error) {
	seen := map[string]bool{}
	add := func(out *[]string, s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		*out = append(*out, s)
	}
	var out []string
	if exact, err := windowsNpcapAdapterNameForInterface(iface); err == nil {
		add(&out, exact)
	}
	name := iface.Name
	if strings.HasPrefix(strings.ToUpper(name), `\\DEVICE\\NPF_`) {
		add(&out, name)
	} else {
		add(&out, `\Device\NPF_`+name)
		add(&out, name)
	}
	for _, n := range windowsNpcapAdapterNames() {
		if strings.Contains(strings.ToLower(n), strings.ToLower(name)) {
			add(&out, n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("could not map Windows interface %q (index %d) to an Npcap adapter; verify Npcap is installed and bound to this NIC", iface.Name, iface.Index)
	}
	return out, nil
}
