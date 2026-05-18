package libknock

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/protocol"
)

func TestHTTPServerWrapListenerTLSAccessSucceeds(t *testing.T) {
	secret := testSecret()
	serverTLS, clientTLS := testTLSConfig(t)
	serverTLS.NextProtos = []string{"http/1.1"}
	clientTLS.NextProtos = []string{"http/1.1"}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	cfg := ServerConfig{ServerPort: mustPort(t, raw.Addr()), Secrets: auth.StaticSecrets{"client-a": secret}, ReplayCache: NewMemoryReplayCache(time.Minute), AuthTimeout: time.Second, Protocol: auth.AuthProtocolFrameV1, AcceptProtocols: []auth.AuthProtocol{auth.AuthProtocolFrameV1}}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Libknock") != "" {
			t.Errorf("upper HTTP layer saw libknock header")
		}
		_, _ = w.Write([]byte("ok"))
	})}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(tls.NewListener(WrapListener(raw, cfg), serverTLS)) }()
	defer server.Close()

	d := &Dialer{Config: ClientConfig{ClientID: "client-a", Secret: secret, ServerPort: cfg.ServerPort, Protocol: auth.AuthProtocolFrameV1}}
	transport := &http.Transport{TLSClientConfig: clientTLS, DialContext: d.DialContext}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	resp, err := client.Get("https://" + raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
	if err := server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestUnauthenticatedTCPConnectionIsClosed(t *testing.T) {
	secret := testSecret()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	cfg := ServerConfig{ServerPort: mustPort(t, raw.Addr()), Secrets: auth.StaticSecrets{"client-a": secret}, ReplayCache: NewMemoryReplayCache(time.Minute), AuthTimeout: 100 * time.Millisecond}
	serveErr := make(chan error, 1)
	go func() {
		conn, err := raw.Accept()
		if err != nil {
			serveErr <- err
			return
		}
		_, _, err = ServerAuth(context.Background(), conn, cfg)
		serveErr <- err
	}()
	conn, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := []byte{0}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, readErr := conn.Read(buf)
	if readErr == nil {
		t.Fatal("expected unauthenticated connection to close")
	}
	if err := <-serveErr; err == nil {
		t.Fatal("expected server auth error")
	}
}

func TestWrongSecretIsClosed(t *testing.T) {
	secret := testSecret()
	wrong := testSecret()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	cfg := ServerConfig{ServerPort: mustPort(t, raw.Addr()), Secrets: auth.StaticSecrets{"client-a": secret}, ReplayCache: NewMemoryReplayCache(time.Minute), AuthTimeout: time.Second, Protocol: auth.AuthProtocolFrameV1, AcceptProtocols: []auth.AuthProtocol{auth.AuthProtocolFrameV1}}
	serveErr := make(chan error, 1)
	go func() {
		conn, err := raw.Accept()
		if err != nil {
			serveErr <- err
			return
		}
		_, _, err = ServerAuth(context.Background(), conn, cfg)
		serveErr <- err
	}()
	conn, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := ClientAuth(context.Background(), conn, ClientConfig{ClientID: "client-a", Secret: wrong, ServerPort: cfg.ServerPort, Protocol: auth.AuthProtocolFrameV1}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, readErr := conn.Read([]byte{0})
	if readErr == nil {
		t.Fatal("expected wrong-secret connection to close")
	}
	if err := <-serveErr; !errors.Is(err, auth.ErrAuthFailed) && !errors.Is(err, auth.ErrUnknownClient) {
		t.Fatalf("server err = %v", err)
	}
}

func TestReplayFrameIsRejected(t *testing.T) {
	secret := testSecret()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	port := mustPort(t, raw.Addr())
	frame, err := testBuildAuthFrame("client-a", secret, port, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cfg := ServerConfig{ServerPort: port, Secrets: auth.StaticSecrets{"client-a": secret}, ReplayCache: NewMemoryReplayCache(5 * time.Minute), AuthTimeout: time.Second, Protocol: auth.AuthProtocolFrameV1, AcceptProtocols: []auth.AuthProtocol{auth.AuthProtocolFrameV1}}
	first := serverAuthOnce(t, raw, cfg, frame)
	if first != nil {
		t.Fatalf("first auth err = %v", first)
	}
	second := serverAuthOnce(t, raw, cfg, frame)
	if !errors.Is(second, auth.ErrReplayDetected) {
		t.Fatalf("second auth err = %v, want replay", second)
	}
}

func TestTimestampOutsideWindowIsRejected(t *testing.T) {
	secret := testSecret()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	port := mustPort(t, raw.Addr())
	frame, err := testBuildAuthFrame("client-a", secret, port, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cfg := ServerConfig{ServerPort: port, Secrets: auth.StaticSecrets{"client-a": secret}, ReplayCache: NewMemoryReplayCache(time.Minute), AuthTimeout: time.Second, TimeWindow: 50 * time.Millisecond, Protocol: auth.AuthProtocolFrameV1, AcceptProtocols: []auth.AuthProtocol{auth.AuthProtocolFrameV1}}
	err = serverAuthOnce(t, raw, cfg, frame)
	if !errors.Is(err, auth.ErrTimeSkew) {
		t.Fatalf("auth err = %v, want expired timestamp", err)
	}
}

func TestTLSClientHelloIsNotConsumedOrCorrupted(t *testing.T) {
	secret := testSecret()
	serverTLS, clientTLS := testTLSConfig(t)
	serverTLS.NextProtos = []string{"http/1.1"}
	clientTLS.NextProtos = []string{"http/1.1"}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	cfg := ServerConfig{ServerPort: mustPort(t, raw.Addr()), Secrets: auth.StaticSecrets{"client-a": secret}, ReplayCache: NewMemoryReplayCache(time.Minute), AuthTimeout: time.Second, Protocol: auth.AuthProtocolFrameV1, AcceptProtocols: []auth.AuthProtocol{auth.AuthProtocolFrameV1}}
	serverErr := make(chan error, 1)
	go func() {
		conn, err := raw.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		clean, _, err := ServerAuth(context.Background(), conn, cfg)
		if err != nil {
			serverErr <- err
			return
		}
		tlsConn := tls.Server(clean, serverTLS)
		if err := tlsConn.Handshake(); err != nil {
			serverErr <- err
			return
		}
		var b [1]byte
		_, err = tlsConn.Read(b[:])
		if err != nil {
			serverErr <- err
			return
		}
		_, err = tlsConn.Write([]byte{b[0] + 1})
		serverErr <- err
	}()
	base, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := ClientAuth(context.Background(), base, ClientConfig{ClientID: "client-a", Secret: secret, ServerPort: cfg.ServerPort, Protocol: auth.AuthProtocolFrameV1}); err != nil {
		t.Fatal(err)
	}
	client := tls.Client(base, clientTLS)
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{41}); err != nil {
		t.Fatal(err)
	}
	var got [1]byte
	if _, err := io.ReadFull(client, got[:]); err != nil {
		t.Fatal(err)
	}
	if got[0] != 42 {
		t.Fatalf("got %d", got[0])
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func testBuildAuthFrame(clientID string, secret []byte, serverPort int, now time.Time) ([]byte, error) {
	frame, _, err := protocol.BuildFrame(clientID, secret, serverPort, now, 0, "", nil, nil)
	return frame, err
}

func serverAuthOnce(t *testing.T, ln net.Listener, cfg ServerConfig, frame []byte) error {
	t.Helper()
	ch := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- err
			return
		}
		clean, _, err := ServerAuth(context.Background(), conn, cfg)
		if clean != nil {
			_ = clean.Close()
		}
		ch <- err
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Write(frame)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	return <-ch
}

func testSecret() []byte {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}
	return secret
}

func mustPort(t *testing.T, addr net.Addr) int {
	t.Helper()
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr is %T", addr)
	}
	return tcp.Port
}

func testTLSConfig(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("append cert")
	}
	server := &tls.Config{Certificates: []tls.Certificate{cert}}
	client := &tls.Config{RootCAs: pool, ServerName: "localhost"}
	return server, client
}
