package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/libknock/libknock"
	"github.com/libknock/libknock/examples/internal/exampleutil"
)

func main() {
	secret := exampleutil.MustSecret()
	raw, err := net.Listen("tcp", env("LIBKNOCK_ADDR", ":9003"))
	if err != nil {
		log.Fatal(err)
	}
	ln := libknock.WrapListener(raw, libknock.ServerConfig{ServerPort: exampleutil.MustPort(raw.Addr()), Secrets: libknock.NewStaticSecretResolver(map[string][]byte{"client-001": secret})})
	cert, err := selfSignedCert()
	if err != nil {
		log.Fatal(err)
	}
	ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	log.Printf("tls server listening on %s", raw.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			defer conn.Close()
			_, _ = conn.Write([]byte("hello from tls over libknock\n"))
		}()
	}
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

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
