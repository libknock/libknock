package knock

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
)

const (
	ipv4VersionIHL        = 0x45 // IPv4 version 4 with a 20-byte header and no IP options.
	ipv6VersionTraffic    = 0x60 // IPv6 version 6 with zero traffic class/flow label.
	defaultPacketTTL      = 64
	ipv4HeaderLen         = 20
	ipv6HeaderLen         = 40
	tcpHeaderLenWithTSOpt = 32
	ipv4ProtocolTCP       = 6
	ipv4ProtocolUDP       = 17
	tcpFlagSYN            = 0x02
	tcpFlagACK            = 0x10
	tcpFlagRST            = 0x04
	tcpOptionEOL          = 0
	tcpOptionNOP          = 1
	tcpOptionTS           = 8
)

func outboundIPv4(remote *net.TCPAddr) (net.IP, error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: remote.IP, Port: remote.Port})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP.To4() == nil {
		return nil, errors.New("could not determine outbound IPv4 address")
	}
	return local.IP.To4(), nil
}

func outboundIPv6(remote *net.TCPAddr) (net.IP, error) {
	conn, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: remote.IP, Port: remote.Port, Zone: remote.Zone})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP.To16() == nil || local.IP.To4() != nil {
		return nil, errors.New("could not determine outbound IPv6 address")
	}
	return local.IP.To16(), nil
}

func buildSYNPacket(srcIP, dstIP net.IP, srcPort, dstPort int, fields SYNFields) ([]byte, error) {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return nil, errors.New("IPv4 source and destination are required")
	}

	packet := make([]byte, ipv4HeaderLen+tcpHeaderLenWithTSOpt)

	// The raw IPv4 header is built explicitly because this path injects a SYN-shaped knock rather than using the kernel TCP stack.
	ip := packet[:ipv4HeaderLen]
	ip[0] = ipv4VersionIHL
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(packet)))
	ipID, err := randomUint16()
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(ip[4:6], ipID)
	ip[8] = defaultPacketTTL
	ip[9] = ipv4ProtocolTCP
	copy(ip[12:16], src4)
	copy(ip[16:20], dst4)
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))

	// TCP carries the authenticated knock fields in sequence/window/timestamp while remaining a valid SYN header.
	tcp := packet[ipv4HeaderLen:]
	binary.BigEndian.PutUint16(tcp[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcp[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(tcp[4:8], fields.Sequence)
	tcp[12] = byte(tcpHeaderLenWithTSOpt/4) << 4
	tcp[13] = tcpFlagSYN
	binary.BigEndian.PutUint16(tcp[14:16], fields.Window)
	tcp[20] = tcpOptionNOP
	tcp[21] = tcpOptionNOP
	tcp[22] = tcpOptionTS
	tcp[23] = 10
	binary.BigEndian.PutUint32(tcp[24:28], fields.Timestamp)
	binary.BigEndian.PutUint32(tcp[28:32], 0)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(src4, dst4, tcp))

	return packet, nil
}

func buildSYNPacketIPv6(srcIP, dstIP net.IP, srcPort, dstPort int, fields SYNFields) ([]byte, error) {
	src16 := srcIP.To16()
	dst16 := dstIP.To16()
	if src16 == nil || dst16 == nil || srcIP.To4() != nil || dstIP.To4() != nil {
		return nil, errors.New("IPv6 source and destination are required")
	}

	packet := make([]byte, ipv6HeaderLen+tcpHeaderLenWithTSOpt)

	// IPv6 has no header checksum; the TCP checksum below authenticates the IPv6 pseudo-header plus TCP payload.
	ip := packet[:ipv6HeaderLen]
	ip[0] = ipv6VersionTraffic
	binary.BigEndian.PutUint16(ip[4:6], uint16(tcpHeaderLenWithTSOpt))
	ip[6] = ipv4ProtocolTCP
	ip[7] = defaultPacketTTL
	copy(ip[8:24], src16)
	copy(ip[24:40], dst16)

	// TCP carries the authenticated knock fields in sequence/window/timestamp while remaining a valid SYN header.
	tcp := packet[ipv6HeaderLen:]
	binary.BigEndian.PutUint16(tcp[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcp[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(tcp[4:8], fields.Sequence)
	tcp[12] = byte(tcpHeaderLenWithTSOpt/4) << 4
	tcp[13] = tcpFlagSYN
	binary.BigEndian.PutUint16(tcp[14:16], fields.Window)
	tcp[20] = tcpOptionNOP
	tcp[21] = tcpOptionNOP
	tcp[22] = tcpOptionTS
	tcp[23] = 10
	binary.BigEndian.PutUint32(tcp[24:28], fields.Timestamp)
	binary.BigEndian.PutUint32(tcp[28:32], 0)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksumIPv6(src16, dst16, tcp))

	return packet, nil
}

func parseSYNPacket(frame []byte) (net.IP, int, SYNFields, bool) {
	if src, dst, fields, ok := parseSYNPacketIPv6(frame); ok {
		return src, dst, fields, true
	}
	ipOff := findIPv4Offset(frame)
	if ipOff < 0 || len(frame) < ipOff+20 {
		return nil, 0, SYNFields{}, false
	}
	ip := frame[ipOff:]
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return nil, 0, SYNFields{}, false
	}
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	if total <= ihl || len(ip) < total {
		total = len(ip)
	}
	if ip[9] != ipv4ProtocolTCP {
		return nil, 0, SYNFields{}, false
	}
	tcp := ip[ihl:total]
	dst, fields, ok := parseSYNFieldsFromTCP(tcp)
	if !ok {
		return nil, 0, SYNFields{}, false
	}
	return net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4(), dst, fields, true
}

func parseSYNPacketIPv6(frame []byte) (net.IP, int, SYNFields, bool) {
	ipOff := findIPv6Offset(frame)
	if ipOff < 0 || len(frame) < ipOff+40 {
		return nil, 0, SYNFields{}, false
	}
	ip := frame[ipOff:]
	payloadLen := int(binary.BigEndian.Uint16(ip[4:6]))
	if ip[6] != ipv4ProtocolTCP || payloadLen < 20 || len(ip) < 40+payloadLen {
		return nil, 0, SYNFields{}, false
	}
	dst, fields, ok := parseSYNFieldsFromTCP(ip[40 : 40+payloadLen])
	if !ok {
		return nil, 0, SYNFields{}, false
	}
	src := make(net.IP, net.IPv6len)
	copy(src, ip[8:24])
	return src, dst, fields, true
}

func parseSYNFieldsFromTCP(tcp []byte) (int, SYNFields, bool) {
	if len(tcp) < 20 {
		return 0, SYNFields{}, false
	}
	flags := tcp[13]
	if flags&tcpFlagSYN == 0 || flags&(tcpFlagACK|tcpFlagRST) != 0 {
		return 0, SYNFields{}, false
	}
	tcpHeaderLen := int(tcp[12]>>4) * 4
	if tcpHeaderLen < 20 || len(tcp) < tcpHeaderLen {
		return 0, SYNFields{}, false
	}
	ts, ok := parseTimestamp(tcp[20:tcpHeaderLen])
	if !ok {
		return 0, SYNFields{}, false
	}
	fields := SYNFields{Sequence: binary.BigEndian.Uint32(tcp[4:8]), Window: binary.BigEndian.Uint16(tcp[14:16]), Timestamp: ts}
	return int(binary.BigEndian.Uint16(tcp[2:4])), fields, true
}

func parseSYNKnock(frame []byte, dstPort int) (net.IP, SYNFields, bool) {
	if src, fields, ok := parseSYNKnockIPv6(frame, dstPort); ok {
		return src, fields, true
	}
	ipOff := findIPv4Offset(frame)
	if ipOff < 0 || len(frame) < ipOff+20 {
		return nil, SYNFields{}, false
	}

	ip := frame[ipOff:]
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return nil, SYNFields{}, false
	}
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	if total <= ihl || len(ip) < total {
		total = len(ip)
	}
	if ip[9] != ipv4ProtocolTCP {
		return nil, SYNFields{}, false
	}

	tcp := ip[ihl:total]
	if len(tcp) < 20 {
		return nil, SYNFields{}, false
	}
	if int(binary.BigEndian.Uint16(tcp[2:4])) != dstPort {
		return nil, SYNFields{}, false
	}
	flags := tcp[13]
	if flags&tcpFlagSYN == 0 || flags&(tcpFlagACK|tcpFlagRST) != 0 {
		return nil, SYNFields{}, false
	}
	tcpHeaderLen := int(tcp[12]>>4) * 4
	if tcpHeaderLen < 20 || len(tcp) < tcpHeaderLen {
		return nil, SYNFields{}, false
	}
	ts, ok := parseTimestamp(tcp[20:tcpHeaderLen])
	if !ok {
		return nil, SYNFields{}, false
	}

	src := net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()
	fields := SYNFields{Sequence: binary.BigEndian.Uint32(tcp[4:8]), Window: binary.BigEndian.Uint16(tcp[14:16]), Timestamp: ts}
	return src, fields, true
}

func parseSYNKnockIPv6(frame []byte, dstPort int) (net.IP, SYNFields, bool) {
	ipOff := findIPv6Offset(frame)
	if ipOff < 0 || len(frame) < ipOff+40 {
		return nil, SYNFields{}, false
	}
	ip := frame[ipOff:]
	payloadLen := int(binary.BigEndian.Uint16(ip[4:6]))
	if ip[6] != ipv4ProtocolTCP || payloadLen < 20 || len(ip) < 40+payloadLen {
		return nil, SYNFields{}, false
	}
	tcp := ip[40 : 40+payloadLen]
	if int(binary.BigEndian.Uint16(tcp[2:4])) != dstPort {
		return nil, SYNFields{}, false
	}
	flags := tcp[13]
	if flags&tcpFlagSYN == 0 || flags&(tcpFlagACK|tcpFlagRST) != 0 {
		return nil, SYNFields{}, false
	}
	tcpHeaderLen := int(tcp[12]>>4) * 4
	if tcpHeaderLen < 20 || len(tcp) < tcpHeaderLen {
		return nil, SYNFields{}, false
	}
	ts, ok := parseTimestamp(tcp[20:tcpHeaderLen])
	if !ok {
		return nil, SYNFields{}, false
	}
	src := make(net.IP, net.IPv6len)
	copy(src, ip[8:24])
	fields := SYNFields{Sequence: binary.BigEndian.Uint32(tcp[4:8]), Window: binary.BigEndian.Uint16(tcp[14:16]), Timestamp: ts}
	return src, fields, true
}

func findIPv4Offset(frame []byte) int { return findIPv4OffsetForProtocol(frame, ipv4ProtocolTCP) }

func findIPv4OffsetForProtocol(frame []byte, protocol byte) int {
	if len(frame) >= 14 {
		etherType := binary.BigEndian.Uint16(frame[12:14])
		switch etherType {
		case 0x0800:
			return 14
		case 0x8100, 0x88a8:
			if len(frame) >= 18 && binary.BigEndian.Uint16(frame[16:18]) == 0x0800 {
				return 18
			}
		}
	}
	max := 64
	if len(frame) < max {
		max = len(frame)
	}
	for i := 0; i+20 <= max; i++ {
		if frame[i]>>4 == 4 && frame[i]&0x0f >= 5 {
			total := int(binary.BigEndian.Uint16(frame[i+2 : i+4]))
			if total >= 20 && i+total <= len(frame) && frame[i+9] == protocol {
				return i
			}
		}
	}
	return -1
}

func findIPv6Offset(frame []byte) int { return findIPv6OffsetForProtocol(frame, ipv4ProtocolTCP) }

func findIPv6OffsetForProtocol(frame []byte, protocol byte) int {
	if len(frame) >= 14 {
		etherType := binary.BigEndian.Uint16(frame[12:14])
		switch etherType {
		case 0x86dd:
			return 14
		case 0x8100, 0x88a8:
			if len(frame) >= 18 && binary.BigEndian.Uint16(frame[16:18]) == 0x86dd {
				return 18
			}
		}
	}
	max := 64
	if len(frame) < max {
		max = len(frame)
	}
	for i := 0; i+40 <= max; i++ {
		payloadLen := int(binary.BigEndian.Uint16(frame[i+4 : i+6]))
		if frame[i]>>4 == 6 && frame[i+6] == protocol && payloadLen >= 8 && i+40+payloadLen <= len(frame) {
			return i
		}
	}
	return -1
}

func parseTimestamp(options []byte) (uint32, bool) {
	for i := 0; i < len(options); {
		kind := options[i]
		switch kind {
		case tcpOptionEOL:
			return 0, false
		case tcpOptionNOP:
			i++
			continue
		default:
			if i+1 >= len(options) {
				return 0, false
			}
			length := int(options[i+1])
			if length < 2 || i+length > len(options) {
				return 0, false
			}
			if kind == tcpOptionTS && length == 10 {
				return binary.BigEndian.Uint32(options[i+2 : i+6]), true
			}
			i += length
		}
	}
	return 0, false
}

func tcpChecksum(srcIP, dstIP net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = ipv4ProtocolTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	return checksum(pseudo)
}

func tcpChecksumIPv6(srcIP, dstIP net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 40+len(tcp))
	copy(pseudo[0:16], srcIP.To16())
	copy(pseudo[16:32], dstIP.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(tcp)))
	pseudo[39] = ipv4ProtocolTCP
	copy(pseudo[40:], tcp)
	return checksum(pseudo)
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) > 1 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func randomEphemeralPort() (int, error) {
	n, err := randomUint16()
	if err != nil {
		return 0, err
	}
	return 32768 + int(n%28232), nil
}

func randomUint16() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

func htons(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }
