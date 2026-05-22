package auth

import "testing"

func BenchmarkReplayCacheCheckAndMark(b *testing.B) {
	cache := NewMemoryReplayCacheWithLimit(DefaultTimeWindow, b.N+1)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := cache.CheckAndMark("client", []byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOnAuthenticatedCallback(b *testing.B) {
	cb := func(PeerInfo) {}
	peer := PeerInfo{PeerIdentity: PeerIdentity{ClientID: "client"}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cb(peer)
	}
}

func BenchmarkOnAuthenticatedBoundedQueue(b *testing.B) {
	ch := make(chan PeerInfo, 1024)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range ch {
		}
	}()
	peer := PeerInfo{PeerIdentity: PeerIdentity{ClientID: "client"}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		select {
		case ch <- peer:
		default:
		}
	}
	close(ch)
	<-done
}
