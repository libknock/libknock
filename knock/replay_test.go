package knock

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/libknock/libknock/auth"
)

func TestBuildKnockFrameRequiresStrongSecret(t *testing.T) {
	if _, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: nil, ServerPort: 443, Method: UDPMethod}); !errors.Is(err, auth.ErrInvalidSecret) {
		t.Fatalf("BuildKnockFrame weak secret = %v, want ErrInvalidSecret", err)
	}
	if _, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: []byte("0123456789abcdef0123456789abcdef"), ServerPort: 70000, Method: UDPMethod}); err == nil {
		t.Fatal("invalid knock frame port was accepted")
	}
}

func TestValidateClientSecrets(t *testing.T) {
	if err := ValidateClientSecrets([]ClientSecret{{ClientID: "client", Secret: []byte("short")}}); !errors.Is(err, auth.ErrInvalidSecret) {
		t.Fatalf("weak client secret = %v, want ErrInvalidSecret", err)
	}
	if err := ValidateClientSecrets([]ClientSecret{{ClientID: "", Secret: []byte("0123456789abcdef0123456789abcdef")}}); !errors.Is(err, auth.ErrInvalidClientID) {
		t.Fatalf("empty client id = %v, want ErrInvalidClientID", err)
	}
}

func TestValidateSendOptions(t *testing.T) {
	if err := ValidateSendOptions(SendOptions{ClientID: "client", Secret: []byte("short")}); !errors.Is(err, auth.ErrInvalidSecret) {
		t.Fatalf("weak send secret = %v, want ErrInvalidSecret", err)
	}
	if err := ValidateSendOptions(SendOptions{ClientID: "", Secret: []byte("0123456789abcdef0123456789abcdef")}); !errors.Is(err, auth.ErrInvalidClientID) {
		t.Fatalf("empty send client id = %v, want ErrInvalidClientID", err)
	}
	if err := ValidateSendOptions(SendOptions{ClientID: "client", Secret: []byte("0123456789abcdef0123456789abcdef"), ServerPort: 0}); err == nil {
		t.Fatal("invalid send port was accepted")
	}
}

func TestBuildOpenKnockFrameRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	sessionID := []byte("0123456789abcdef")
	packet, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: secret, ServerPort: 443, Method: UDPMethod, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	info, err := ParseKnockFrameUnsafe(packet, ServerConfig{Clients: []ClientSecret{{ClientID: "client", Secret: secret}}, ServerPort: 443, Method: UDPMethod})
	if err != nil {
		t.Fatal(err)
	}
	if info.ClientID != "client" || info.Method != UDPMethod || info.ServerPort != 443 || !bytes.Equal(info.SessionID, sessionID) {
		t.Fatalf("unexpected knock info: %+v", info)
	}
}

func TestKnockFrameRejectsWrongSecretAndHint(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	packet, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: secret, ServerPort: 443, Method: UDPMethod})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKnockFrameUnsafe(packet, ServerConfig{Clients: []ClientSecret{{ClientID: "client", Secret: []byte("fedcba9876543210fedcba9876543210")}}, ServerPort: 443, Method: UDPMethod}); !errors.Is(err, auth.ErrUnknownClient) {
		t.Fatalf("wrong secret err = %v, want unknown client", err)
	}
	packet[16] ^= 0x80
	if _, err := ParseKnockFrameUnsafe(packet, ServerConfig{Clients: []ClientSecret{{ClientID: "client", Secret: secret}}, ServerPort: 443, Method: UDPMethod}); !errors.Is(err, auth.ErrUnknownClient) {
		t.Fatalf("wrong key hint err = %v, want unknown client", err)
	}
}

func TestKnockFrameRejectsTimestampReservedTruncatedAndRandom(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	oldPacket, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: secret, ServerPort: 443, Method: UDPMethod, Timestamp: time.Now().Add(-2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	cfg := ServerConfig{Clients: []ClientSecret{{ClientID: "client", Secret: secret}}, ServerPort: 443, Method: UDPMethod, TimeWindow: time.Second}
	if _, err := ParseKnockFrameUnsafe(oldPacket, cfg); !errors.Is(err, auth.ErrTimeSkew) {
		t.Fatalf("old timestamp err = %v, want time skew", err)
	}
	packet, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: secret, ServerPort: 443, Method: UDPMethod})
	if err != nil {
		t.Fatal(err)
	}
	packet[27] = 1
	if _, err := ParseKnockFrameUnsafe(packet, cfg); !errors.Is(err, auth.ErrInvalidFrame) {
		t.Fatalf("reserved err = %v, want invalid frame", err)
	}
	if _, err := ParseKnockFrameUnsafe(packet[:KnockFrameHeaderSize-1], cfg); !errors.Is(err, auth.ErrInvalidFrame) {
		t.Fatalf("truncated err = %v, want invalid frame", err)
	}
	if _, err := ParseKnockFrameUnsafe([]byte("not a libknock frame"), cfg); !errors.Is(err, auth.ErrInvalidFrame) {
		t.Fatalf("random payload err = %v, want invalid frame", err)
	}
	if _, err := ParseKnockFrameUnsafe([]byte(`{"client_id":"client","method":"udp"}`), cfg); !errors.Is(err, auth.ErrInvalidFrame) {
		t.Fatalf("json payload err = %v, want invalid frame", err)
	}
}

func TestKnockFrameReplayCacheRejectsSameFrame(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	cache := auth.NewMemoryReplayCache(time.Minute)
	packet, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: secret, ServerPort: 443, Method: UDPMethod})
	if err != nil {
		t.Fatal(err)
	}
	cfg := ServerConfig{Clients: []ClientSecret{{ClientID: "client", Secret: secret}}, ServerPort: 443, Method: UDPMethod, ReplayCache: cache}
	if _, err := OpenKnockFrame(packet, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKnockFrame(packet, cfg); !errors.Is(err, auth.ErrReplayDetected) {
		t.Fatalf("second OpenKnockFrame = %v, want ErrReplayDetected", err)
	}
}

func TestKnockFrameDoesNotExposeStablePlaintextFields(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	clientID := "client-plaintext-marker"
	packet, err := BuildKnockFrame(KnockFrameOptions{ClientID: clientID, Secret: secret, ServerPort: 443, Method: UDPMethod})
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range [][]byte{[]byte(clientID), []byte("client_id"), []byte("method"), []byte("timestamp"), []byte("hmac")} {
		if bytes.Contains(packet, marker) {
			t.Fatalf("packet exposed plaintext marker %q", marker)
		}
	}
}

func TestListenUDPRejectsReplay(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	addr := freeUDPAddr(t)
	cache := auth.NewMemoryReplayCache(time.Minute)
	done := make(chan Event, 2)
	errCh := make(chan error, 1)
	invalid := make(chan string, 2)
	ctx, cancel := contextWithTimeout(t, time.Second)
	defer cancel()
	go func() {
		errCh <- ListenUDP(ctx, addr, ListenOptions{Port: 443, Clients: []ClientSecret{{ClientID: "client", Secret: secret}}, ReplayCache: cache, InvalidPacket: func(_ net.IP, reason string) { invalid <- reason }}, func(ev Event) { done <- ev })
	}()
	packet, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: secret, ServerPort: 443, Method: UDPMethod})
	if err != nil {
		t.Fatal(err)
	}
	for {
		sendUDPDatagram(t, addr, packet)
		select {
		case <-done:
			goto accepted
		case err := <-errCh:
			t.Fatal(err)
		case <-time.After(10 * time.Millisecond):
		}
	}
accepted:
	sendUDPDatagram(t, addr, packet)
	select {
	case ev := <-done:
		t.Fatalf("replayed knock accepted: %+v", ev)
	case reason := <-invalid:
		if reason != auth.ErrReplayDetected.Error() {
			t.Fatalf("invalid reason = %q, want replay", reason)
		}
	case <-time.After(100 * time.Millisecond):
	}
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	_ = conn.Close()
	return addr
}

func sendUDPDatagram(t *testing.T, addr string, data []byte) {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}
}

func contextWithTimeout(t *testing.T, d time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), d)
}

func FuzzOpenKnockFrame(f *testing.F) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	frame, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: secret, ServerPort: 443, Method: UDPMethod})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(frame)
	f.Add([]byte(`{"client_id":"client","method":"udp"}`))
	f.Add([]byte("random udp payload"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = OpenKnockFrame(data, ServerConfig{Clients: []ClientSecret{{ClientID: "client", Secret: secret}}, ServerPort: 443, Method: UDPMethod, ReplayCache: auth.NewMemoryReplayCache(time.Minute)})
	})
}

func TestOpenKnockFrameRequiresReplayCache(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	packet, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: secret, ServerPort: 443, Method: UDPMethod})
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenKnockFrame(packet, ServerConfig{Clients: []ClientSecret{{ClientID: "client", Secret: secret}}, ServerPort: 443, Method: UDPMethod})
	if !errors.Is(err, auth.ErrMissingReplayCache) {
		t.Fatalf("OpenKnockFrame err = %v, want missing replay cache", err)
	}
}

func TestKnockReplayCacheFailsClosedAtLimit(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	cache := auth.NewMemoryReplayCacheWithLimit(time.Minute, 2)
	cfg := ServerConfig{Clients: []ClientSecret{{ClientID: "client", Secret: secret}}, ServerPort: 443, Method: UDPMethod, ReplayCache: cache}
	packets := make([][]byte, 3)
	for i := range packets {
		packet, err := BuildKnockFrame(KnockFrameOptions{ClientID: "client", Secret: secret, ServerPort: 443, Method: UDPMethod})
		if err != nil {
			t.Fatal(err)
		}
		packets[i] = packet
	}
	if _, err := OpenKnockFrame(packets[0], cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKnockFrame(packets[1], cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKnockFrame(packets[2], cfg); !errors.Is(err, auth.ErrReplayCacheFull) {
		t.Fatalf("third frame err = %v, want ErrReplayCacheFull", err)
	}
	if _, err := OpenKnockFrame(packets[0], cfg); !errors.Is(err, auth.ErrReplayDetected) {
		t.Fatalf("first frame replay err = %v, want ErrReplayDetected", err)
	}
}
