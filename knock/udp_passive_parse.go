package knock

import (
	"encoding/binary"
	"net"
)

func parseUDPKnockDatagram(frame []byte, dstPort int) (net.IP, []byte, bool) {
	if src, payload, ok := parseUDPKnockIPv6(frame, dstPort); ok {
		return src, payload, true
	}
	return parseUDPKnockIPv4(frame, dstPort)
}

func parseUDPKnockIPv4(frame []byte, dstPort int) (net.IP, []byte, bool) {
	ipOff := findIPv4OffsetForProtocol(frame, ipv4ProtocolUDP)
	if ipOff < 0 || len(frame) < ipOff+20 {
		return nil, nil, false
	}
	ip := frame[ipOff:]
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return nil, nil, false
	}
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	if total <= ihl || len(ip) < total {
		total = len(ip)
	}
	if ip[9] != ipv4ProtocolUDP {
		return nil, nil, false
	}
	payload, ok := parseUDPPayload(ip[ihl:total], dstPort)
	if !ok {
		return nil, nil, false
	}
	return net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4(), payload, true
}

func parseUDPKnockIPv6(frame []byte, dstPort int) (net.IP, []byte, bool) {
	ipOff := findIPv6OffsetForProtocol(frame, ipv4ProtocolUDP)
	if ipOff < 0 || len(frame) < ipOff+40 {
		return nil, nil, false
	}
	ip := frame[ipOff:]
	payloadLen := int(binary.BigEndian.Uint16(ip[4:6]))
	if ip[6] != ipv4ProtocolUDP || payloadLen < 8 || len(ip) < 40+payloadLen {
		return nil, nil, false
	}
	payload, ok := parseUDPPayload(ip[40:40+payloadLen], dstPort)
	if !ok {
		return nil, nil, false
	}
	src := make(net.IP, net.IPv6len)
	copy(src, ip[8:24])
	return src, payload, true
}

func parseUDPPayload(udp []byte, dstPort int) ([]byte, bool) {
	if len(udp) < 8 {
		return nil, false
	}
	if int(binary.BigEndian.Uint16(udp[2:4])) != dstPort {
		return nil, false
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || udpLen > len(udp) {
		return nil, false
	}
	return udp[8:udpLen], true
}
