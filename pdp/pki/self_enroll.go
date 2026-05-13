package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SelfEnrollResult holds the TLS certificate and CA PEM obtained via
// direct Vault PKI enrollment at PDP startup.
type SelfEnrollResult struct {
	Certificate *tls.Certificate
	CAPEM       []byte
	ExpiresAt   time.Time
}

// SelfEnroll connects directly to Vault PKI, creates a CSR for the configured FQDN
// using the provided ECDSA key (or generates a new one if nil), signs it via the
// PDP PKI role, and returns a tls.Certificate ready for use as the server's TLS identity.
//
// This replaces static TLS material with a Vault-issued certificate and a
// Transit-protected private key.
func SelfEnroll(ctx context.Context, cfg VaultConfig, pdpFQDN, rolePDP string, existingKey *ecdsa.PrivateKey) (*SelfEnrollResult, error) {
	if strings.TrimSpace(pdpFQDN) == "" {
		return nil, fmt.Errorf("pdp_fqdn is required for self-enrollment")
	}
	role := strings.TrimSpace(rolePDP)
	if role == "" {
		return nil, fmt.Errorf("pki_role_pdp is required for self-enrollment")
	}

	// 1. Use existing key or generate new ECDSA P-256 keypair
	key := existingKey
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate PDP key: %w", err)
		}
	}

	// 2. Create CSR with the PDP FQDN
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   pdpFQDN,
			Organization: []string{"ZTNA PDP"},
		},
		DNSNames: []string{pdpFQDN},
	}
	if ip := net.ParseIP(pdpFQDN); ip != nil {
		tmpl.DNSNames = nil
		tmpl.IPAddresses = []net.IP{ip}
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("create PDP CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// 3. Connect to Vault
	client, err := NewVaultClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create Vault client: %w", err)
	}

	// 4. Sign CSR via Vault PKI
	log.Printf("[PDP-SELF-ENROLL] Requesting certificate from Vault PKI (role=%s, fqdn=%s)", role, pdpFQDN)
	certBundle, err := client.SignCSR(csrPEM, role, "")
	if err != nil {
		return nil, fmt.Errorf("Vault sign CSR: %w", err)
	}

	// 5. Get CA certificate for mTLS client verification
	caPEM, err := client.GetCAPEM()
	if err != nil {
		return nil, fmt.Errorf("get CA PEM: %w", err)
	}

	// 6. Parse the signed certificate to build tls.Certificate
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal PDP key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certBundle, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse TLS key pair: %w", err)
	}

	// 7. Extract expiry
	certBlock, _ := pem.Decode(certBundle)
	if certBlock == nil {
		return nil, fmt.Errorf("decode enrolled certificate PEM")
	}
	parsedCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse enrolled certificate: %w", err)
	}

	return &SelfEnrollResult{
		Certificate: &tlsCert,
		CAPEM:       caPEM,
		ExpiresAt:   parsedCert.NotAfter,
	}, nil
}

// SelfEnrollLoop periodically checks certificate expiration and renews
// before expiry. dataDir is the PDP's data directory for persisting certs.
func SelfEnrollLoop(ctx context.Context, cfg VaultConfig, pdpFQDN, rolePDP string, key *ecdsa.PrivateKey, certPath, caPath, dataDir string, renewThreshold, checkInterval time.Duration, onRenew func(*tls.Certificate)) {
	if checkInterval <= 0 {
		checkInterval = 6 * time.Hour
	}
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !shouldRenew(certPath, renewThreshold) {
				continue
			}
			log.Printf("[PDP-SELF-ENROLL] Certificate near expiry, renewing...")
			result, err := SelfEnroll(ctx, cfg, pdpFQDN, rolePDP, key)
			if err != nil {
				log.Printf("[PDP-SELF-ENROLL] Renewal failed: %v", err)
				continue
			}
			if err := SaveEnrolledCert(result, certPath, caPath, dataDir); err != nil {
				log.Printf("[PDP-SELF-ENROLL] Save renewed cert failed: %v", err)
				continue
			}
			if onRenew != nil {
				onRenew(result.Certificate)
			}
			log.Printf("[PDP-SELF-ENROLL] Certificate renewed (expires=%s)", result.ExpiresAt.Format(time.RFC3339))
		}
	}
}

// SaveEnrolledCert persists the enrolled certificate and CA to disk.
// The private key is stored separately as Vault Transit encrypted ciphertext.
func SaveEnrolledCert(result *SelfEnrollResult, certPath, caPath, dataDir string) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return fmt.Errorf("create PDP cert directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(caPath), 0o700); err != nil {
		return fmt.Errorf("create CA cert directory: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: result.Certificate.Certificate[0],
	})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write PDP cert: %w", err)
	}

	if err := os.WriteFile(caPath, result.CAPEM, 0o644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}

	return nil
}

// shouldRenew checks whether the certificate at certPath is within
// the renewal threshold of its NotAfter.
func shouldRenew(certPath string, threshold time.Duration) bool {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return true // No cert means we need enrollment
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	return time.Until(cert.NotAfter) < threshold
}
