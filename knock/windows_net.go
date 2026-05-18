//go:build windows

package knock

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

func windowsResolveMAC(ctx context.Context, iface *net.Interface, targetIP net.IP) (net.HardwareAddr, error) {
	if targetIP == nil || targetIP.To4() == nil {
		return nil, fmt.Errorf("invalid IPv4 next hop")
	}
	if mac, ok := windowsARPTableLookup(targetIP); ok {
		return mac, nil
	}
	_ = pingOnce(ctx, targetIP)
	if mac, ok := windowsARPTableLookup(targetIP); ok {
		return mac, nil
	}
	return nil, fmt.Errorf("could not resolve MAC address for next hop %s on %s; verify gateway reachability", targetIP, iface.Name)
}

func windowsARPTableLookup(targetIP net.IP) (net.HardwareAddr, bool) {
	out, err := exec.Command("arp", "-a", targetIP.String()).Output()
	if err != nil {
		return nil, false
	}
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 2 || fields[0] != targetIP.String() {
			continue
		}
		mac, err := net.ParseMAC(strings.ReplaceAll(fields[1], "-", ":"))
		if err == nil && len(mac) == 6 {
			return mac, true
		}
	}
	return nil, false
}

func pingOnce(ctx context.Context, ip net.IP) error {
	c, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	return exec.CommandContext(c, "ping", "-n", "1", "-w", "1000", ip.String()).Run()
}

func buildEthernetIPv4Frame(srcMAC, dstMAC net.HardwareAddr, ipPacket []byte) []byte {
	frame := make([]byte, 14+len(ipPacket))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	copy(frame[14:], ipPacket)
	return frame
}
