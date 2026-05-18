package grpcintegration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	libknock "github.com/libknock/libknock"
	"github.com/libknock/libknock/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestGRPCServerWrapListenerTLSAccessSucceeds(t *testing.T) {
	secret := testSecret()
	serverTLS, clientTLS := testTLSConfig(t)
	serverTLS.NextProtos = []string{"h2"}
	clientTLS.NextProtos = []string{"h2"}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	cfg := libknock.ServerConfig{ServerPort: mustPort(t, raw.Addr()), Secrets: auth.StaticSecrets{"client-a": secret}, AuthTimeout: time.Second}
	server := grpc.NewServer()
	registerTestPinger(server)
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(tls.NewListener(libknock.WrapListener(raw, cfg), serverTLS)) }()
	defer server.Stop()

	d := &libknock.Dialer{Config: libknock.ClientConfig{ClientID: "client-a", Secret: secret, ServerPort: cfg.ServerPort}}
	dialCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, "passthrough:///"+raw.Addr().String(), grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) { return d.DialContext(ctx, "tcp", address) }), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)), grpc.WithBlock())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var out emptypb.Empty
	if err := conn.Invoke(context.Background(), "/libknock.test.Pinger/Ping", &emptypb.Empty{}, &out); err != nil {
		t.Fatal(err)
	}
	server.Stop()
	if err := <-serveErr; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

type testPingerServer interface {
	Ping(context.Context, *emptypb.Empty) (*emptypb.Empty, error)
}
type testPinger struct{}

func (testPinger) Ping(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func registerTestPinger(s *grpc.Server) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "libknock.test.Pinger",
		HandlerType: (*testPingerServer)(nil),
		Methods: []grpc.MethodDesc{{MethodName: "Ping", Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
			in := new(emptypb.Empty)
			if err := dec(in); err != nil {
				return nil, err
			}
			if interceptor == nil {
				return srv.(testPingerServer).Ping(ctx, in)
			}
			info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/libknock.test.Pinger/Ping"}
			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				return srv.(testPingerServer).Ping(ctx, req.(*emptypb.Empty))
			}
			return interceptor(ctx, in, info, handler)
		}}},
	}, testPinger{})
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
