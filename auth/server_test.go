package auth

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/libknock/libknock/protocol"
)

func TestUnsupportedWireVersionIsRejected(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	client, server := net.Pipe()
	defer client.Close()
	cfg := ServerConfig{ServerPort: 443, Secrets: StaticSecrets{"client": secret}, ReplayCache: NewMemoryReplayCache(time.Minute), AuthTimeout: time.Second, Protocol: AuthProtocolFrameV1, AcceptProtocols: []AuthProtocol{AuthProtocolFrameV1}}
	done := make(chan error, 1)
	go func() {
		_, _, err := ServerAuth(context.Background(), server, cfg)
		done <- err
	}()
	frame, _, err := protocol.BuildFrame("client", secret, 443, time.Now(), 0, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	frame[0] = protocol.Version + 1
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("ServerAuth err = %v, want unsupported version", err)
	}
}

func TestClientAuthRejectsOversizedClientID(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	_, err := ClientAuthWithInfo(context.Background(), client, ClientConfig{ClientID: string(make([]byte, 65536)), Secret: []byte("0123456789abcdef"), ServerPort: 443})
	if !errors.Is(err, ErrInvalidClientID) {
		t.Fatalf("ClientAuthWithInfo err = %v, want invalid client ID", err)
	}
}

func TestNewServerSharesReplayCacheAcrossAuthCalls(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	server, err := NewServer(ServerConfig{ServerPort: 443, Secrets: StaticSecrets{"client": secret}, ReplayCache: NewMemoryReplayCache(time.Minute), AuthTimeout: time.Second, Protocol: AuthProtocolFrameV1, AcceptProtocols: []AuthProtocol{AuthProtocolFrameV1}})
	if err != nil {
		t.Fatal(err)
	}
	frame, _, err := protocol.BuildFrame("client", secret, 443, time.Now(), 0, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		clientConn, serverConn := net.Pipe()
		done := make(chan error, 1)
		go func() {
			clean, _, err := server.Auth(context.Background(), serverConn)
			if clean != nil {
				_ = clean.Close()
			}
			done <- err
		}()
		if _, err := clientConn.Write(frame); err != nil {
			t.Fatal(err)
		}
		_ = clientConn.Close()
		err := <-done
		if i == 0 && err != nil {
			t.Fatalf("first Auth err = %v", err)
		}
		if i == 1 && !errors.Is(err, ErrReplayDetected) {
			t.Fatalf("second Auth err = %v, want replay", err)
		}
	}
}

func TestClientConfigMetadataRoundTripsToPeer(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	client, server := net.Pipe()
	defer client.Close()
	cfg := ServerConfig{ServerPort: 443, Secrets: StaticSecrets{"client": secret}, ReplayCache: NewMemoryReplayCache(time.Minute), AuthTimeout: time.Second, Protocol: AuthProtocolFrameV1, AcceptProtocols: []AuthProtocol{AuthProtocolFrameV1}}
	done := make(chan *PeerInfo, 1)
	go func() {
		clean, peer, err := ServerAuth(context.Background(), server, cfg)
		if err != nil {
			done <- nil
			return
		}
		defer clean.Close()
		if fromConn, ok := PeerFromConn(clean); ok {
			peer = &fromConn
		}
		done <- peer
	}()
	wantSession := []byte("session-1")
	wantExtensions := []byte{1, 2, 3}
	if _, err := ClientAuthWithInfo(context.Background(), client, ClientConfig{ClientID: "client", Secret: secret, ServerPort: 443, Protocol: AuthProtocolFrameV1, Method: "udp-seq", SessionID: wantSession, Extensions: wantExtensions}); err != nil {
		t.Fatal(err)
	}
	peer := <-done
	if peer == nil {
		t.Fatal("server auth failed")
	}
	if peer.Method != "udp-seq" || string(peer.SessionID) != string(wantSession) || string(peer.Extensions) != string(wantExtensions) {
		t.Fatalf("peer metadata = method %q session %q extensions %v", peer.Method, peer.SessionID, peer.Extensions)
	}
	if ctxPeer, ok := PeerFromContext(ContextWithPeer(context.Background(), *peer)); !ok || ctxPeer.ClientID != "client" {
		t.Fatalf("context peer = %+v ok=%v", ctxPeer, ok)
	}
}

func TestOptionalServerProof(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	client, serverConn := net.Pipe()
	defer client.Close()
	cfg := ServerConfig{ServerPort: 443, Secrets: StaticSecrets{"client": secret}, ReplayCache: NewMemoryReplayCache(time.Minute), AuthTimeout: time.Second, Protocol: AuthProtocolFrameV1, AcceptProtocols: []AuthProtocol{AuthProtocolFrameV1}, ServerProof: true}
	done := make(chan error, 1)
	go func() {
		clean, _, err := ServerAuth(context.Background(), serverConn, cfg)
		if clean != nil {
			_ = clean.Close()
		}
		done <- err
	}()
	if _, err := ClientAuthWithInfo(context.Background(), client, ClientConfig{ClientID: "client", Secret: secret, ServerPort: 443, Protocol: AuthProtocolFrameV1, RequireServerProof: true}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRotatingSecretResolverMatchesCurrentSecret(t *testing.T) {
	oldSecret := []byte("old-secret-0123456789abcdef")
	newSecret := []byte("new-secret-0123456789abcdef")
	var nonce [16]byte
	copy(nonce[:], []byte("1234567890123456"))
	meta := FrameMeta{Hint: protocol.ComputeKeyHint(newSecret, nonce, 443), Nonce: nonce, ServerPort: 443}
	candidates, err := NewRotatingSecretResolver(map[string][][]byte{"client": [][]byte{oldSecret, newSecret}}).ResolveCandidates(meta)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || string(candidates[0].Secret) != string(newSecret) {
		t.Fatalf("candidates = %#v", candidates)
	}
}

type failingResolver struct{}

func (failingResolver) ResolveCandidates(FrameMeta) ([]SecretCandidate, error) {
	return nil, errors.New("kms unavailable")
}

type manyCandidateResolver struct {
	candidates []SecretCandidate
}

func (r manyCandidateResolver) ResolveCandidates(FrameMeta) ([]SecretCandidate, error) {
	return r.candidates, nil
}

func TestServerAuthDistinguishesSecretResolverFailure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	cfg := ServerConfig{ServerPort: 443, Secrets: failingResolver{}, ReplayCache: NewMemoryReplayCache(time.Minute), AuthTimeout: time.Second}
	done := make(chan error, 1)
	go func() {
		_, _, err := ServerAuth(context.Background(), server, cfg)
		done <- err
	}()
	frame, _, err := protocol.BuildFrame("client", []byte("0123456789abcdef0123456789abcdef"), 443, time.Now(), 0, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrSecretResolverFailed) {
		t.Fatalf("ServerAuth err = %v, want resolver failure", err)
	}
}

func TestServerAuthFailureJitterDelaysClose(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	cfg := ServerConfig{ServerPort: 443, Secrets: StaticSecrets{"client": []byte("0123456789abcdef0123456789abcdef")}, ReplayCache: NewMemoryReplayCache(time.Minute), AuthTimeout: time.Second, FailDelayJitterMin: 20 * time.Millisecond, FailDelayJitterMax: 20 * time.Millisecond}
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		_, _, _ = ServerAuth(context.Background(), server, cfg)
		done <- time.Since(start)
	}()
	frame, _, err := protocol.BuildFrame("client", []byte("abcdef0123456789abcdef0123456789"), 443, time.Now(), 0, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	if elapsed := <-done; elapsed < 15*time.Millisecond {
		t.Fatalf("failure returned too quickly after jitter: %v", elapsed)
	}
}

func TestEnvelopeV2ClientServerAuth(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	client, server := net.Pipe()
	defer client.Close()
	cfg := ServerConfig{ServerPort: 443, Secrets: StaticSecrets{"client": secret}, ReplayCache: NewMemoryReplayCache(time.Minute), AuthTimeout: time.Second, Protocol: AuthProtocolEnvelopeV2, AcceptProtocols: []AuthProtocol{AuthProtocolEnvelopeV2}, ServerProof: true}
	done := make(chan *PeerInfo, 1)
	go func() {
		clean, peer, err := ServerAuth(context.Background(), server, cfg)
		if clean != nil {
			_ = clean.Close()
		}
		if err != nil {
			done <- nil
			return
		}
		done <- peer
	}()
	if _, err := ClientAuthWithInfo(context.Background(), client, ClientConfig{ClientID: "client", Secret: secret, ServerPort: 443, Protocol: AuthProtocolEnvelopeV2, RequireServerProof: true}); err != nil {
		t.Fatal(err)
	}
	peer := <-done
	if peer == nil || peer.Protocol != AuthProtocolEnvelopeV2 || len(peer.Nonce) != protocol.EnvelopeV2PrefixSize {
		t.Fatalf("peer = %+v", peer)
	}
}

func TestEnvelopeV2PreservesBufferedApplicationBytes(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan []byte, 1)
	go func() {
		clean, _, err := ServerAuth(context.Background(), server, ServerConfig{ServerPort: 443, Secrets: StaticSecrets{"client": secret}, ReplayCache: NewMemoryReplayCache(time.Minute), AuthTimeout: time.Second, Protocol: AuthProtocolEnvelopeV2, AcceptProtocols: []AuthProtocol{AuthProtocolEnvelopeV2}})
		if err != nil {
			done <- nil
			return
		}
		defer clean.Close()
		buf := make([]byte, 5)
		_, _ = io.ReadFull(clean, buf)
		done <- buf
	}()
	frame, _, err := protocol.BuildEnvelopeV2("client", secret, 443, time.Now(), 0, "", nil, nil, protocol.EnvelopeV2Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(append(frame, []byte("hello")...)); err != nil {
		t.Fatal(err)
	}
	if got := <-done; string(got) != "hello" {
		t.Fatalf("buffered bytes = %q", got)
	}
}

func TestEnvelopeV2HintModeNoneClientServerAuth(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	client, server := net.Pipe()
	defer client.Close()
	env := EnvelopeV2Config{HintMode: HintModeNone}
	done := make(chan error, 1)
	go func() {
		clean, _, err := ServerAuth(context.Background(), server, ServerConfig{ServerPort: 443, Secrets: StaticSecrets{"client": secret}, ReplayCache: NewMemoryReplayCache(time.Minute), AuthTimeout: time.Second, Protocol: AuthProtocolEnvelopeV2, AcceptProtocols: []AuthProtocol{AuthProtocolEnvelopeV2}, EnvelopeV2: env})
		if clean != nil {
			_ = clean.Close()
		}
		done <- err
	}()
	if _, err := ClientAuthWithInfo(context.Background(), client, ClientConfig{ClientID: "client", Secret: secret, ServerPort: 443, Protocol: AuthProtocolEnvelopeV2, EnvelopeV2: env}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestEnvelopeV2MaxAuthAttempts(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	frame, _, err := protocol.BuildEnvelopeV2("client", secret, 443, time.Now(), 0, "", nil, nil, protocol.EnvelopeV2Config{})
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	cfg := ServerConfig{
		ServerPort:      443,
		Secrets:         manyCandidateResolver{candidates: []SecretCandidate{{ClientID: "wrong-1", Secret: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}, {ClientID: "client", Secret: secret}}},
		ReplayCache:     NewMemoryReplayCache(time.Minute),
		AuthTimeout:     time.Second,
		Protocol:        AuthProtocolEnvelopeV2,
		AcceptProtocols: []AuthProtocol{AuthProtocolEnvelopeV2},
		MaxAuthAttempts: 1,
	}
	done := make(chan error, 1)
	go func() {
		clean, _, err := ServerAuth(context.Background(), server, cfg)
		if clean != nil {
			_ = clean.Close()
		}
		done <- err
	}()
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrTooManyCandidates) {
		t.Fatalf("ServerAuth err = %v, want too many candidates", err)
	}
}

func TestProtocolCompatibilityMatrix(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	testPair := func(name string, serverCfg ServerConfig, clientCfg ClientConfig, wantErr bool) {
		t.Helper()
		client, server := net.Pipe()
		defer client.Close()
		done := make(chan error, 1)
		go func() {
			clean, _, err := ServerAuth(context.Background(), server, serverCfg)
			if clean != nil {
				_ = clean.Close()
			}
			done <- err
		}()
		err := ClientAuth(context.Background(), client, clientCfg)
		serverErr := <-done
		if wantErr && err == nil && serverErr == nil {
			t.Fatalf("%s succeeded unexpectedly", name)
		}
		if !wantErr && (err != nil || serverErr != nil) {
			t.Fatalf("%s client=%v server=%v", name, err, serverErr)
		}
	}
	baseServer := ServerConfig{ServerPort: 443, Secrets: StaticSecrets{"client": secret}, ReplayCache: NewMemoryReplayCache(time.Minute), AuthTimeout: time.Second, Protocol: AuthProtocolFrameV1, AcceptProtocols: []AuthProtocol{AuthProtocolFrameV1}}
	baseClient := ClientConfig{ClientID: "client", Secret: secret, ServerPort: 443, Protocol: AuthProtocolFrameV1}
	s := baseServer
	s.Protocol = AuthProtocolEnvelopeV2
	s.AcceptProtocols = []AuthProtocol{AuthProtocolEnvelopeV2}
	testPair("v1 client to v2 server", s, baseClient, true)
	c := baseClient
	c.Protocol = AuthProtocolEnvelopeV2
	testPair("v2 client to v1 server", baseServer, c, true)
	s.AcceptProtocols = []AuthProtocol{AuthProtocolFrameV1, AuthProtocolEnvelopeV2}
	testPair("dual accepts v1", s, baseClient, false)
	testPair("dual accepts v2", s, c, false)
}

type recordingKnockStore struct{ peer PeerInfo }

func (s *recordingKnockStore) CheckAndConsume(peer PeerInfo, remote net.Addr) error {
	s.peer = peer
	return nil
}

func TestEnvelopeV2RequireKnockCarriesSessionID(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	sessionID := []byte("session-id-0001!")
	store := &recordingKnockStore{}
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		clean, _, err := ServerAuth(context.Background(), server, ServerConfig{ServerPort: 443, Secrets: StaticSecrets{"client": secret}, ReplayCache: NewMemoryReplayCache(time.Minute), AuthTimeout: time.Second, Protocol: AuthProtocolEnvelopeV2, AcceptProtocols: []AuthProtocol{AuthProtocolEnvelopeV2}, RequireKnock: true, KnockStore: store})
		if clean != nil {
			_ = clean.Close()
		}
		done <- err
	}()
	if err := ClientAuth(context.Background(), client, ClientConfig{ClientID: "client", Secret: secret, ServerPort: 443, Protocol: AuthProtocolEnvelopeV2, SessionID: sessionID}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if string(store.peer.SessionID) != string(sessionID) || store.peer.Protocol != AuthProtocolEnvelopeV2 {
		t.Fatalf("knock peer = %+v", store.peer)
	}
}

func TestNewServerAutoReplayCacheRejectsReplayAcrossConnections(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	server, err := NewServer(ServerConfig{ServerPort: 443, Secrets: StaticSecrets{"client": secret}, Protocol: AuthProtocolFrameV1, AcceptProtocols: []AuthProtocol{AuthProtocolFrameV1}})
	if err != nil {
		t.Fatal(err)
	}
	frame, _, err := protocol.BuildFrame("client", secret, 443, time.Now(), 0, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		clientConn, serverConn := net.Pipe()
		done := make(chan error, 1)
		go func() {
			clean, _, err := server.Auth(context.Background(), serverConn)
			if clean != nil {
				_ = clean.Close()
			}
			done <- err
		}()
		if _, err := clientConn.Write(frame); err != nil {
			t.Fatal(err)
		}
		_ = clientConn.Close()
		err := <-done
		if i == 0 && err != nil {
			t.Fatalf("first Auth err = %v", err)
		}
		if i == 1 && !errors.Is(err, ErrReplayDetected) {
			t.Fatalf("second Auth err = %v, want replay", err)
		}
	}
}
