//go:build windows

package knock

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsRoute struct {
	destination net.IP
	mask        net.IPMask
	gateway     net.IP
	ifIndex     int
	prefixLen   int
	source      string
}

func (r windowsRoute) contains(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil || r.destination == nil || r.mask == nil {
		return false
	}
	return r.destination.Equal(ip4.Mask(r.mask))
}

func windowsIPv4Routes() ([]windowsRoute, error) {
	var all []windowsRoute
	var errs []string
	for _, loader := range []struct {
		name string
		fn   func() ([]windowsRoute, error)
	}{
		{"GetIpForwardTable2", windowsIPv4RoutesFromIPHelper},
		{"PowerShell Get-NetRoute", windowsIPv4RoutesFromPowerShell},
		{"route print -4", windowsIPv4RoutesFromRoutePrint},
	} {
		routes, err := loader.fn()
		if err != nil {
			errs = append(errs, loader.name+": "+err.Error())
			continue
		}
		if len(routes) == 0 {
			errs = append(errs, loader.name+": no routes")
			continue
		}
		all = append(all, routes...)
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no IPv4 routes found; tried %s", strings.Join(errs, "; "))
	}
	return all, nil
}

func windowsIPv4RoutesFromIPHelper() ([]windowsRoute, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return nil, fmt.Errorf("GetIpForwardTable2(AF_INET) failed: %w", err)
	}
	if table == nil {
		return nil, fmt.Errorf("GetIpForwardTable2(AF_INET) returned nil table")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))

	out := make([]windowsRoute, 0, table.NumEntries)
	for _, row := range table.Rows() {
		if row.DestinationPrefix.Prefix.Family != windows.AF_INET || row.NextHop.Family != windows.AF_INET {
			continue
		}
		prefixLen := int(row.DestinationPrefix.PrefixLength)
		if prefixLen < 0 || prefixLen > 32 {
			continue
		}
		dst := sockaddrIPv4(row.DestinationPrefix.Prefix)
		gw := sockaddrIPv4(row.NextHop)
		if dst == nil || gw == nil {
			continue
		}
		out = append(out, windowsRoute{destination: dst.Mask(net.CIDRMask(prefixLen, 32)), mask: net.CIDRMask(prefixLen, 32), gateway: gw, ifIndex: int(row.InterfaceIndex), prefixLen: prefixLen, source: "iphelper"})
	}
	return out, nil
}

func sockaddrIPv4(a windows.RawSockaddrInet) net.IP {
	if a.Family != windows.AF_INET {
		return nil
	}
	a4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&a))
	return net.IPv4(a4.Addr[0], a4.Addr[1], a4.Addr[2], a4.Addr[3]).To4()
}

func windowsIPv4RoutesFromPowerShell() ([]windowsRoute, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-Command", "Get-NetRoute -AddressFamily IPv4 | Select-Object ifIndex,DestinationPrefix,NextHop | ConvertTo-Csv -NoTypeInformation").Output()
	if err != nil {
		return nil, err
	}
	return parsePowerShellRoutes(out)
}

func parsePowerShellRoutes(out []byte) ([]windowsRoute, error) {
	s := bufio.NewScanner(bytes.NewReader(stripUTF16LEBOM(out)))
	if !s.Scan() {
		return nil, fmt.Errorf("empty PowerShell output")
	}
	var routes []windowsRoute
	for s.Scan() {
		fields := parseCSVLine(s.Text())
		if len(fields) < 3 {
			continue
		}
		ifIndex, err := strconv.Atoi(strings.TrimSpace(fields[0]))
		if err != nil {
			continue
		}
		dst, mask, bits, ok := parseCIDRv4(strings.TrimSpace(fields[1]))
		if !ok {
			continue
		}
		gw := net.ParseIP(strings.TrimSpace(fields[2])).To4()
		if gw == nil {
			gw = net.IPv4zero
		}
		routes = append(routes, windowsRoute{destination: dst, mask: mask, gateway: gw, ifIndex: ifIndex, prefixLen: bits, source: "powershell"})
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return routes, nil
}

func windowsIPv4RoutesFromRoutePrint() ([]windowsRoute, error) {
	out, err := exec.Command("route", "print", "-4").Output()
	if err != nil {
		return nil, err
	}
	return parseRoutePrint(out)
}

func parseRoutePrint(out []byte) ([]windowsRoute, error) {
	s := bufio.NewScanner(bytes.NewReader(out))
	inRoutes := false
	var routes []windowsRoute
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		if strings.Contains(line, "Network Destination") && strings.Contains(line, "Netmask") {
			inRoutes = true
			continue
		}
		if !inRoutes {
			continue
		}
		if strings.HasPrefix(line, "====") || strings.Contains(line, "Persistent Routes") || strings.Contains(line, "永久路由") {
			break
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		dst := net.ParseIP(fields[0]).To4()
		maskIP := net.ParseIP(fields[1]).To4()
		gw := net.ParseIP(fields[2]).To4()
		ifIndex, err := strconv.Atoi(fields[4])
		if dst == nil || maskIP == nil || gw == nil || err != nil {
			continue
		}
		mask := net.IPMask(maskIP)
		bits, total := mask.Size()
		if total != 32 || bits < 0 {
			continue
		}
		routes = append(routes, windowsRoute{destination: dst.Mask(mask), mask: mask, gateway: gw, ifIndex: ifIndex, prefixLen: bits, source: "route-print"})
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return routes, nil
}

func parseCIDRv4(v string) (net.IP, net.IPMask, int, bool) {
	ip, ipNet, err := net.ParseCIDR(v)
	if err != nil || ip.To4() == nil {
		return nil, nil, 0, false
	}
	bits, total := ipNet.Mask.Size()
	if total != 32 || bits < 0 {
		return nil, nil, 0, false
	}
	return ip.To4().Mask(ipNet.Mask), ipNet.Mask, bits, true
}

func parseCSVLine(line string) []string {
	line = strings.TrimSpace(line)
	var fields []string
	var b strings.Builder
	inQuotes := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch c {
		case '"':
			if inQuotes && i+1 < len(line) && line[i+1] == '"' {
				b.WriteByte('"')
				i++
			} else {
				inQuotes = !inQuotes
			}
		case ',':
			if inQuotes {
				b.WriteByte(c)
			} else {
				fields = append(fields, b.String())
				b.Reset()
			}
		default:
			b.WriteByte(c)
		}
	}
	fields = append(fields, b.String())
	return fields
}

func stripUTF16LEBOM(b []byte) []byte {
	if len(b) < 2 || b[0] != 0xff || b[1] != 0xfe {
		return b
	}
	u := make([]byte, 0, len(b)/2)
	for i := 2; i+1 < len(b); i += 2 {
		if b[i+1] == 0 {
			u = append(u, b[i])
		}
	}
	return u
}
