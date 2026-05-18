//go:build linux

package knock

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestParseUDPKnockIPv4(t *testing.T) {
	payload := []byte{0x01, 0x02, 0xa0, 0xff}
	packet := make([]byte, 14+20+8+len(payload))
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	ip := packet[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+len(payload)))
	ip[9] = ipv4ProtocolUDP
	copy(ip[12:16], net.IPv4(192, 0, 2, 10).To4())
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[2:4], 443)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)
	src, got, ok := parseUDPKnockDatagram(packet, 443)
	if !ok {
		t.Fatal("expected UDP knock packet to parse")
	}
	if src.String() != "192.0.2.10" {
		t.Fatalf("unexpected source IP %s", src)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload mismatch: got %q", got)
	}
}

func TestParseUDPKnockIPv6(t *testing.T) {
	payload := []byte{0x01, 0x02, 0xa0, 0xff}
	packet := make([]byte, 14+40+8+len(payload))
	binary.BigEndian.PutUint16(packet[12:14], 0x86dd)
	ip := packet[14:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(8+len(payload)))
	ip[6] = ipv4ProtocolUDP
	src := net.ParseIP("2001:db8::10").To16()
	copy(ip[8:24], src)
	udp := ip[40:]
	binary.BigEndian.PutUint16(udp[2:4], 443)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)
	gotSrc, got, ok := parseUDPKnockDatagram(packet, 443)
	if !ok {
		t.Fatal("expected UDP knock packet to parse")
	}
	if gotSrc.String() != "2001:db8::10" {
		t.Fatalf("unexpected source IP %s", gotSrc)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload mismatch: got %q", got)
	}
}
