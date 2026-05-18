package knock

import (
	"net"
	"testing"
	"time"
)

var benchKnockSecret = []byte("0123456789abcdef0123456789abcdef")

func BenchmarkKnockFrameBuildOpen(b *testing.B) {
	frame, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: benchKnockSecret, ServerPort: 443, Method: UDPMethod, SessionID: []byte("session-id-0001!")})
	if err != nil {
		b.Fatal(err)
	}
	cfg := ServerConfig{Clients: []ClientSecret{{ClientID: "client", Secret: benchKnockSecret}}, ServerPort: 443, Method: UDPMethod}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := OpenKnockFrame(frame, cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSequenceTracker(b *testing.B) {
	seqID := []byte("sequence-id-0001")
	infos := []*KnockInfo{buildBenchSequenceInfo(b, seqID, 0), buildBenchSequenceInfo(b, seqID, 1)}
	src := net.ParseIP("192.0.2.1")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tr := newSequenceTracker(SequenceOptions{Length: 2, Window: time.Second, MaxInflightPerIP: 8, MaxTotalInflight: 8}, time.Minute)
		if ok, err := tr.add(src, infos[0], time.Now()); err != nil || ok {
			b.Fatalf("part1 ok=%v err=%v", ok, err)
		}
		if ok, err := tr.add(src, infos[1], time.Now()); err != nil || !ok {
			b.Fatalf("part2 ok=%v err=%v", ok, err)
		}
	}
}

func buildBenchSequenceInfo(b testing.TB, seqID []byte, idx int) *KnockInfo {
	b.Helper()
	frame, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: benchKnockSecret, ServerPort: 443, Method: UDPSeqMethod, SequenceID: seqID, SequenceIndex: idx, SequenceTotal: 2})
	if err != nil {
		b.Fatal(err)
	}
	info, err := OpenKnockFrame(frame, ServerConfig{Clients: []ClientSecret{{ClientID: "client", Secret: benchKnockSecret}}, ServerPort: 443, Method: UDPSeqMethod, AllowSequence: true})
	if err != nil {
		b.Fatal(err)
	}
	return info
}
