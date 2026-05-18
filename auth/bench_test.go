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
