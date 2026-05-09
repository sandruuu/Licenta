//go:build ignore

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func main() {
	// Load CA cert
	caCertPEM, err := os.ReadFile("ca.crt")
	if err != nil {
		panic(fmt.Errorf("read ca.crt: %w", err))
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		panic("failed to decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		panic(fmt.Errorf("parse CA cert: %w", err))
	}

	// Load CA key
	caKeyPEM, err := os.ReadFile("ca.key")
	if err != nil {
		panic(fmt.Errorf("read ca.key: %w", err))
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		panic("failed to decode CA key PEM")
	}
	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		panic(fmt.Errorf("parse CA key: %w", err))
	}

	// Generate server key
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Errorf("generate server key: %w", err))
	}

	// Create server certificate template
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(fmt.Errorf("generate serial: %w", err))
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"ZTNA PDP"},
		},
		DNSNames:    []string{"localhost", "pdp.lab.local"},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Sign with CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		panic(fmt.Errorf("create certificate: %w", err))
	}

	// Write server cert
	certFile, err := os.Create("pdp.crt")
	if err != nil {
		panic(fmt.Errorf("create pdp.crt: %w", err))
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certFile.Close()

	// Write server key
	keyFile, err := os.Create("pdp.key")
	if err != nil {
		panic(fmt.Errorf("create pdp.key: %w", err))
	}
	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		panic(fmt.Errorf("marshal server key: %w", err))
	}
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyFile.Close()

	fmt.Println("✓ Generated pdp.crt (ECDSA P-256, signed by ZTNA Lab CA)")
	fmt.Println("✓ Generated pdp.key (ECDSA P-256 private key)")
	fmt.Println("  SAN: localhost, pdp.lab.local")
	fmt.Println("  Valid: 365 days")
}
