package knock

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/libknock/libknock/auth"
)

func TestUDPSequenceTrackerAcceptsOutOfOrder(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	sequenceID := []byte("sequence-id-0001")
	sessionID := []byte("session-id-0001!")
	now := time.Now()
	infos := make([]*KnockInfo, 3)
	for i := range infos {
		infos[i] = buildSequenceInfo(t, "client", secret, sequenceID, sessionID, i, 3, UDPSeqMethod)
	}
	tr := newSequenceTracker(SequenceOptions{Length: 3, SlotSeconds: 30, Window: time.Second, MaxInflightPerIP: 8, MaxTotalInflight: 8}, time.Minute)
	src := net.ParseIP("192.0.2.1")
	for _, idx := range []int{1, 0} {
		ok, err := tr.add(src, infos[idx], now)
		if err != nil {
			t.Fatalf("part %d: %v", idx, err)
		}
		if ok {
			t.Fatalf("part %d completed early", idx)
		}
	}
	ok, err := tr.add(src, infos[2], now)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("final sequence part did not complete")
	}
	if !bytes.Equal(infos[2].SessionID, sessionID) {
		t.Fatal("session id was not preserved in sequence info")
	}
}

func TestUDPSequenceTrackerRejectsDuplicateAndReplay(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	sequenceID := []byte("sequence-id-0002")
	sessionID := []byte("session-id-0002!")
	now := time.Now()
	first := buildSequenceInfo(t, "client", secret, sequenceID, sessionID, 0, 2, UDPSeqMethod)
	second := buildSequenceInfo(t, "client", secret, sequenceID, sessionID, 1, 2, UDPSeqMethod)
	tr := newSequenceTracker(SequenceOptions{Length: 2, SlotSeconds: 30, Window: time.Second, MaxInflightPerIP: 8, MaxTotalInflight: 8}, time.Minute)
	src := net.ParseIP("192.0.2.1")
	if ok, err := tr.add(src, first, now); err != nil || ok {
		t.Fatalf("first add ok=%v err=%v", ok, err)
	}
	if ok, err := tr.add(src, first, now); err == nil || ok {
		t.Fatalf("duplicate add ok=%v err=%v", ok, err)
	}
	if ok, err := tr.add(src, second, now); err != nil || !ok {
		t.Fatalf("final add ok=%v err=%v", ok, err)
	}
	if ok, err := tr.add(src, first, now); !errors.Is(err, auth.ErrReplayDetected) || ok {
		t.Fatalf("completed replay ok=%v err=%v", ok, err)
	}
}

func TestUDPSequenceTrackerRejectsTimeoutAndLimits(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Now()
	tr := newSequenceTracker(SequenceOptions{Length: 2, SlotSeconds: 30, Window: 10 * time.Millisecond, MaxInflightPerIP: 1, MaxTotalInflight: 1}, time.Minute)
	src := net.ParseIP("192.0.2.1")
	first := buildSequenceInfo(t, "client", secret, []byte("sequence-id-0003"), nil, 0, 2, UDPSeqMethod)
	if ok, err := tr.add(src, first, now); err != nil || ok {
		t.Fatalf("first add ok=%v err=%v", ok, err)
	}
	other := buildSequenceInfo(t, "client", secret, []byte("sequence-id-0004"), nil, 0, 2, UDPSeqMethod)
	if ok, err := tr.add(net.ParseIP("192.0.2.2"), other, now); err == nil || ok {
		t.Fatalf("expected total inflight rejection, ok=%v err=%v", ok, err)
	}
	second := buildSequenceInfo(t, "client", secret, []byte("sequence-id-0003"), nil, 1, 2, UDPSeqMethod)
	if ok, err := tr.add(src, second, now.Add(20*time.Millisecond)); err == nil || ok {
		t.Fatalf("expected timeout rejection, ok=%v err=%v", ok, err)
	}
}

func TestUDPSequenceRejectsInvalidTotalsAndMixedIdentity(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	if _, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: secret, ServerPort: 443, Method: UDPSeqMethod, SequenceID: []byte("sequence-id-0005"), SequenceIndex: 0, SequenceTotal: DefaultSequenceMaxParts + 1}); !errors.Is(err, auth.ErrInvalidFrame) {
		t.Fatalf("oversized total err = %v, want invalid frame", err)
	}
	now := time.Now()
	tr := newSequenceTracker(SequenceOptions{Length: 2, SlotSeconds: 30, Window: time.Second, MaxInflightPerIP: 8, MaxTotalInflight: 8}, time.Minute)
	seqID := []byte("sequence-id-0006")
	if ok, err := tr.add(net.ParseIP("192.0.2.1"), buildSequenceInfo(t, "client-a", secret, seqID, nil, 0, 2, UDPSeqMethod), now); err != nil || ok {
		t.Fatalf("client-a part ok=%v err=%v", ok, err)
	}
	if ok, err := tr.add(net.ParseIP("192.0.2.1"), buildSequenceInfo(t, "client-b", secret, seqID, nil, 1, 2, UDPSeqMethod), now); err != nil || ok {
		t.Fatalf("mixed client part should not complete, ok=%v err=%v", ok, err)
	}
	if ok, err := tr.add(net.ParseIP("192.0.2.2"), buildSequenceInfo(t, "client-a", secret, seqID, nil, 1, 2, UDPSeqMethod), now); err != nil || ok {
		t.Fatalf("mixed remote part should not complete, ok=%v err=%v", ok, err)
	}
}

func buildSequenceInfo(t *testing.T, clientID string, secret, sequenceID, sessionID []byte, index, total int, method string) *KnockInfo {
	t.Helper()
	packet, err := BuildKnockFrame(KnockFrameOptions{ClientID: clientID, Secret: secret, ServerPort: 443, Method: method, SessionID: sessionID, SequenceID: sequenceID, SequenceIndex: index, SequenceTotal: total})
	if err != nil {
		t.Fatal(err)
	}
	info, err := OpenKnockFrame(packet, ServerConfig{Clients: []ClientSecret{{ClientID: clientID, Secret: secret}}, ServerPort: 443, Method: method, AllowSequence: true})
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestSYNSeqUsesProtectedPort(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	slot := int64(1700000000 / 30)
	parts := ComputeSYNSeqParts(secret, "client", 443, slot, 3)
	seen := map[SYNFields]bool{}
	for i, part := range parts {
		if part.Port != 443 {
			t.Fatalf("part %d port = %d, want protected port 443", i, part.Port)
		}
		if seen[part.Fields] {
			t.Fatalf("part %d reused SYN fields %+v", i, part.Fields)
		}
		seen[part.Fields] = true
		clientID, gotSlot, ok := VerifySYNSeqPart(part.Fields, 443, []ClientSecret{{ClientID: "client", Secret: secret}}, 443, time.Unix(slot*30, 0), 30, 3, i, false)
		if !ok || clientID != "client" || gotSlot != slot {
			t.Fatalf("part %d did not verify: client=%q slot=%d ok=%v", i, clientID, gotSlot, ok)
		}
	}
}

func TestSYNSeqVerifyAcceptsLegacyRandomPorts(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	slot := int64(1700000000 / 30)
	parts := computeLegacySYNSeqParts(secret, "client", 443, slot, 3)
	for i, part := range parts {
		if part.Port == 443 {
			t.Fatalf("legacy part %d unexpectedly used protected port", i)
		}
		clientID, gotSlot, ok := VerifySYNSeqPart(part.Fields, part.Port, []ClientSecret{{ClientID: "client", Secret: secret}}, 443, time.Unix(slot*30, 0), 30, 3, i, true)
		if !ok || clientID != "client" || gotSlot != slot {
			t.Fatalf("legacy part %d did not verify: client=%q slot=%d ok=%v", i, clientID, gotSlot, ok)
		}
	}
}

func TestOpenKnockFrameRejectsUnsupportedAndInconsistentFlags(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	packet, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: secret, ServerPort: 443, Method: UDPMethod})
	if err != nil {
		t.Fatal(err)
	}
	packet[26] |= 0x80
	if _, err := OpenKnockFrame(packet, ServerConfig{Clients: []ClientSecret{{ClientID: "client", Secret: secret}}, ServerPort: 443, Method: UDPMethod}); !errors.Is(err, auth.ErrUnsupportedFlags) {
		t.Fatalf("OpenKnockFrame unsupported flags err = %v", err)
	}

	packet, err = BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: secret, ServerPort: 443, Method: UDPMethod})
	if err != nil {
		t.Fatal(err)
	}
	h := decodeKnockHeader(packet[:KnockFrameHeaderSize])
	h.Flags |= KnockFlagSession
	plain, err := encodeKnockPayload(knockPayload{FrameType: KnockFrameTypeUDP, ClientIDHash: ComputeKnockClientIDHash(secret, "client"), TimestampMS: time.Now().UnixMilli(), Method: UDPMethod, ServerPort: 443, ClientRandom: []byte("0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealKnockPayload(secret, h, 443, plain)
	if err != nil {
		t.Fatal(err)
	}
	h.SealedLen = uint16(len(sealed))
	packet = make([]byte, KnockFrameHeaderSize+len(sealed))
	encodeKnockHeader(packet[:KnockFrameHeaderSize], h)
	copy(packet[KnockFrameHeaderSize:], sealed)
	if _, err := OpenKnockFrame(packet, ServerConfig{Clients: []ClientSecret{{ClientID: "client", Secret: secret}}, ServerPort: 443, Method: UDPMethod}); !errors.Is(err, auth.ErrInvalidFrame) {
		t.Fatalf("OpenKnockFrame inconsistent flags err = %v", err)
	}
}

func FuzzSequenceTracker(f *testing.F) {
	f.Add([]byte("sequence-id-0001"), byte(0), byte(2))
	f.Fuzz(func(t *testing.T, seed []byte, idxByte, totalByte byte) {
		if len(seed) == 0 {
			return
		}
		seqID := make([]byte, KnockSequenceIDBytes)
		copy(seqID, seed)
		total := int(totalByte % byte(DefaultSequenceMaxParts+1))
		idx := int(idxByte)
		frame, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: benchKnockSecret, ServerPort: 443, Method: UDPSeqMethod, SequenceID: seqID, SequenceIndex: idx, SequenceTotal: total})
		if err != nil {
			return
		}
		info, err := OpenKnockFrame(frame, ServerConfig{Clients: []ClientSecret{{ClientID: "client", Secret: benchKnockSecret}}, ServerPort: 443, Method: UDPSeqMethod, AllowSequence: true})
		if err != nil {
			return
		}
		_, _ = newSequenceTracker(SequenceOptions{Length: total, Window: time.Second, MaxInflightPerIP: 2, MaxTotalInflight: 2}, time.Minute).add(net.ParseIP("192.0.2.1"), info, time.Now())
	})
}

func TestSYNSeqRejectsLegacyByDefault(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	slot := int64(1700000000 / 30)
	part := computeLegacySYNSeqParts(secret, "client", 443, slot, 3)[0]
	if _, _, ok := VerifySYNSeqPart(part.Fields, part.Port, []ClientSecret{{ClientID: "client", Secret: secret}}, 443, time.Unix(slot*30, 0), 30, 3, 0, false); ok {
		t.Fatal("legacy SYN sequence verified without compatibility flag")
	}
}
