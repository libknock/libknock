package knock

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestSendMethodUDPPassiveSequenceUsesUDPSequenceSender(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	received := make(chan int, 3)
	go func() {
		buf := make([]byte, MaxFrameSize)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				close(received)
				return
			}
			received <- n
		}
	}()
	err = SendMethod(ctx, UDPPassiveSeq, SendOptions{ServerAddr: conn.LocalAddr().String(), ClientID: "client", Secret: []byte("0123456789abcdef0123456789abcdef"), ServerPort: 443, Sequence: SequenceOptions{Length: 2, PacketInterval: time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for n := range received {
		if n == 0 {
			t.Fatal("empty sequence packet")
		}
		count++
		if count == 2 {
			return
		}
	}
	t.Fatalf("received %d packets, want 2", count)
}

func TestValidateClientSecretRejectsOversizedClientID(t *testing.T) {
	if err := ValidateClientSecret(ClientSecret{ClientID: string(make([]byte, 65536)), Secret: []byte("0123456789abcdef")}); err == nil {
		t.Fatal("expected oversized client ID to be rejected")
	}
}
