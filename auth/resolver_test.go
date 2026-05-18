package auth

import (
	"testing"

	"github.com/libknock/libknock/protocol"
)

func TestStaticSecretsResolveCandidatesUsesFrameMeta(t *testing.T) {
	good := []byte("0123456789abcdef0123456789abcdef")
	bad := []byte("abcdef0123456789abcdef0123456789")
	var nonce [16]byte
	copy(nonce[:], []byte("1234567890123456"))
	port := 443
	meta := FrameMeta{Hint: protocol.ComputeKeyHint(good, nonce, port), Nonce: nonce, ServerPort: port}
	candidates, err := (StaticSecrets{"good": good, "bad": bad}).ResolveCandidates(meta)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].ClientID != "good" {
		t.Fatalf("candidates = %#v", candidates)
	}
}

func TestNewStaticSecretResolverCopiesInput(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	resolver := NewStaticSecretResolver(map[string][]byte{"client": secret})
	secret[0] = 'X'
	var nonce [16]byte
	hint := protocol.ComputeKeyHint([]byte("0123456789abcdef0123456789abcdef"), nonce, 443)
	candidates, err := resolver.ResolveCandidates(FrameMeta{Hint: hint, Nonce: nonce, ServerPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(candidates))
	}
	if candidates[0].Secret[0] == 'X' {
		t.Fatal("resolver retained caller-owned secret slice")
	}
}

func TestStaticSecretsResolveCandidatesDeterministic(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	candidates, err := (StaticSecrets{"b": secret, "a": secret, "c": secret}).ResolveCandidates(FrameMeta{Protocol: AuthProtocolEnvelopeV2, HintMode: HintModeNone})
	if err != nil {
		t.Fatal(err)
	}
	got := []string{candidates[0].ClientID, candidates[1].ClientID, candidates[2].ClientID}
	want := []string{"a", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate order = %v, want %v", got, want)
		}
	}
}

func TestRotatingSecretsResolveCandidatesDeterministic(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	candidates, err := (RotatingSecrets{"b": {secret}, "a": {secret}}).ResolveCandidates(FrameMeta{Protocol: AuthProtocolEnvelopeV2, HintMode: HintModeNone})
	if err != nil {
		t.Fatal(err)
	}
	got := []string{candidates[0].ClientID, candidates[1].ClientID}
	want := []string{"a", "b"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate order = %v, want %v", got, want)
		}
	}
}
