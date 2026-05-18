package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	libknock "github.com/libknock/libknock"
	"github.com/libknock/libknock/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/emptypb"
)

type pingerServer interface {
	Ping(context.Context, *emptypb.Empty) (*emptypb.Empty, error)
}
type pinger struct{}

func (pinger) Ping(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func main() {
	secret := mustSecret()
	raw, err := net.Listen("tcp", env("LIBKNOCK_ADDR", ":9004"))
	if err != nil {
		log.Fatal(err)
	}
	cert, err := selfSignedCert()
	if err != nil {
		log.Fatal(err)
	}
	ln := libknock.WrapListener(raw, libknock.ServerConfig{ServerPort: mustPort(raw.Addr()), Secrets: auth.StaticSecrets{"client-001": secret}})
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}})))
	registerPinger(server)
	log.Printf("grpc server listening on %s", raw.Addr())
	log.Fatal(server.Serve(ln))
}

func registerPinger(s *grpc.Server) {
	s.RegisterService(&grpc.ServiceDesc{ServiceName: "libknock.example.Pinger", HandlerType: (*pingerServer)(nil), Methods: []grpc.MethodDesc{{MethodName: "Ping", Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
		in := new(emptypb.Empty)
		if err := dec(in); err != nil {
			return nil, err
		}
		if interceptor == nil {
			return srv.(pingerServer).Ping(ctx, in)
		}
		info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/libknock.example.Pinger/Ping"}
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return srv.(pingerServer).Ping(ctx, req.(*emptypb.Empty))
		}
		return interceptor(ctx, in, info, handler)
	}}}}, pinger{})
}

func selfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return tls.X509KeyPair(certPEM, keyPEM)
}
func mustSecret() []byte {
	secret, err := base64.StdEncoding.DecodeString(os.Getenv("LIBKNOCK_SECRET_BASE64"))
	if err != nil || len(secret) < auth.MinSecretSize {
		log.Fatal("set LIBKNOCK_SECRET_BASE64 to at least 16 random bytes")
	}
	return secret
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func mustPort(addr net.Addr) int {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.Port
	}
	return 0
}
