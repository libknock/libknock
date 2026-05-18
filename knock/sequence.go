package knock

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"time"
)

const (
	Version           = 1
	UDPSeqMethod      = "udp-seq"
	UDPPassiveSeq     = "udp-passive-seq"
	TCP_SYNSeqMethod  = "tcp-syn-seq"
	UDPSeqDefaultSlot = 30 * time.Second
	synSeqLabel       = "libknock/tcp-syn-seq/v1"
	legacySYNSeqLabel = "knock-proxy/tcp-syn-seq/v1"
)

type SYNFields struct {
	Sequence  uint32
	Window    uint16
	Timestamp uint32
}

type SYNSeqPart struct {
	Port   int
	Fields SYNFields
}

func ComputeSYNSeqParts(secret []byte, clientID string, protectedPort int, slot int64, total int) []SYNSeqPart {
	return computeSYNSeqParts(secret, clientID, protectedPort, slot, total, false)
}

func computeLegacySYNSeqParts(secret []byte, clientID string, protectedPort int, slot int64, total int) []SYNSeqPart {
	return computeSYNSeqParts(secret, clientID, protectedPort, slot, total, true)
}

func computeSYNSeqParts(secret []byte, clientID string, protectedPort int, slot int64, total int, legacyRandomPorts bool) []SYNSeqPart {
	if total < 2 || total > 5 {
		total = 3
	}
	out := make([]SYNSeqPart, total)
	for i := range out {
		mac := hmac.New(sha256.New, secret)
		if legacyRandomPorts {
			mac.Write([]byte(legacySYNSeqLabel))
		} else {
			mac.Write([]byte(synSeqLabel))
		}
		writeString(mac, clientID)
		writeUint16(mac, uint16(protectedPort))
		writeInt64(mac, slot)
		writeUint16(mac, uint16(i))
		tag := mac.Sum(nil)
		port := protectedPort
		if legacyRandomPorts {
			port = 1024 + int(binary.BigEndian.Uint16(tag[0:2])%64511)
		}
		window := binary.BigEndian.Uint16(tag[6:8])
		if window == 0 {
			window = 1
		}
		out[i] = SYNSeqPart{Port: port, Fields: SYNFields{Sequence: binary.BigEndian.Uint32(tag[2:6]), Window: window, Timestamp: binary.BigEndian.Uint32(tag[8:12])}}
	}
	return out
}

func VerifySYNSeqPart(fields SYNFields, dstPort int, clients []ClientSecret, protectedPort int, now time.Time, slotSeconds, total, index int, allowLegacy bool) (string, int64, bool) {
	if slotSeconds <= 0 {
		slotSeconds = 30
	}
	current := now.Unix() / int64(slotSeconds)
	for _, client := range clients {
		for _, delta := range []int64{-1, 0, 1} {
			slot := current + delta
			if synSeqPartMatches(ComputeSYNSeqParts(client.Secret, client.ClientID, protectedPort, slot, total), index, dstPort, fields) || (allowLegacy && synSeqPartMatches(computeLegacySYNSeqParts(client.Secret, client.ClientID, protectedPort, slot, total), index, dstPort, fields)) {
				return client.ClientID, slot, true
			}
		}
	}
	return "", 0, false
}

func normalizedSequenceOptions(opts SequenceOptions) SequenceOptions {
	if opts.Length == 0 {
		opts.Length = 3
	}
	if opts.SlotSeconds == 0 {
		opts.SlotSeconds = 30
	}
	if opts.Window <= 0 {
		opts.Window = 10 * time.Second
	}
	if opts.PacketInterval <= 0 {
		opts.PacketInterval = 80 * time.Millisecond
	}
	if opts.MaxInflightPerIP == 0 {
		opts.MaxInflightPerIP = 8
	}
	if opts.MaxTotalInflight == 0 {
		opts.MaxTotalInflight = 4096
	}
	return opts
}

func synSeqPartMatches(parts []SYNSeqPart, index, dstPort int, fields SYNFields) bool {
	return index >= 0 && index < len(parts) && parts[index].Port == dstPort && parts[index].Fields == fields
}

func writeString(w io.Writer, s string) { writeUint16(w, uint16(len(s))); _, _ = w.Write([]byte(s)) }
func writeUint16(w io.Writer, v uint16) {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	_, _ = w.Write(buf[:])
}
func writeInt64(w io.Writer, v int64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(v))
	_, _ = w.Write(buf[:])
}
