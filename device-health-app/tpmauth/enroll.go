package tpmauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// EnrollmentResult holds the result of a successful enrollment.
type EnrollmentResult struct {
	CertPEM []byte
	CAPEM   []byte
	ID      string
}

// enrollmentResponse mirrors models.EnrollmentResponse from the cloud.
type enrollmentResponse struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	CertPEM string `json:"cert_pem,omitempty"`
	CAPEM   string `json:"ca_pem,omitempty"`
	Message string `json:"message,omitempty"`
}

// enrollmentRequest mirrors models.EnrollmentRequest from the cloud.
type enrollmentRequest struct {
	DeviceID             string `json:"device_id"`
	Component            string `json:"component"`
	Hostname             string `json:"hostname"`
	CSRPEM               string `json:"csr_pem"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
}

// PublicKeyFingerprint returns the SHA-256 hex fingerprint of a public key.
func PublicKeyFingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:]), nil
}

// CreateCSR generates a PEM-encoded Certificate Signing Request signed by the given signer.
func CreateCSR(signer crypto.Signer, deviceID, hostname string) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   deviceID,
			Organization: []string{"ZeroTrust Device"},
		},
		DNSNames: []string{hostname},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// Enroll submits a CSR to the cloud enrollment API and returns immediately.
func Enroll(cloudURL, caFile, certSHA256, deviceID, hostname string, csrPEM []byte, pubKeyFingerprint string) (enrollmentID string, err error) {
	client, err := enrollHTTPClient(caFile, certSHA256)
	if err != nil {
		return "", err
	}

	reqBody := enrollmentRequest{
		DeviceID:             deviceID,
		Component:            "health",
		Hostname:             hostname,
		CSRPEM:               string(csrPEM),
		PublicKeyFingerprint: pubKeyFingerprint,
	}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal enrollment request: %w", err)
	}

	url := strings.TrimRight(cloudURL, "/") + "/api/enroll"
	resp, err := client.Post(url, "application/json", strings.NewReader(string(bodyJSON)))
	if err != nil {
		return "", fmt.Errorf("POST /api/enroll: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var enrollResp enrollmentResponse
	if err := json.Unmarshal(body, &enrollResp); err != nil {
		return "", fmt.Errorf("parse enrollment response: %w", err)
	}

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		slog.Warn("Enrollment rejected", "http_status", resp.StatusCode)
		return "", fmt.Errorf("enrollment rejected by server (HTTP %d)", resp.StatusCode)
	}

	return enrollResp.ID, nil
}

// WaitForApproval polls the enrollment status endpoint until approved or revoked.
// Uses exponential backoff: starts at pollInterval, doubles up to 60s max.
func WaitForApproval(ctx context.Context, cloudURL, caFile, certSHA256, deviceID string, pollInterval time.Duration) (*EnrollmentResult, error) {
	client, err := enrollHTTPClient(caFile, certSHA256)
	if err != nil {
		return nil, err
	}

	statusURL := strings.TrimRight(cloudURL, "/") + "/api/enroll/status?device_id=" + deviceID

	currentInterval := pollInterval
	maxInterval := 60 * time.Second

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("enrollment cancelled: %w", ctx.Err())
		default:
		}

		slog.Info("Polling enrollment status...", "device_id", deviceID, "interval", currentInterval)

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("enrollment cancelled: %w", ctx.Err())
			}
			slog.Warn("Enrollment poll failed, retrying", "error", err)
			sleepWithContext(ctx, currentInterval)
			currentInterval = nextBackoff(currentInterval, maxInterval)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var enrollResp enrollmentResponse
		if err := json.Unmarshal(body, &enrollResp); err != nil {
			slog.Warn("Invalid poll response, retrying", "error", err)
			sleepWithContext(ctx, currentInterval)
			currentInterval = nextBackoff(currentInterval, maxInterval)
			continue
		}

		switch enrollResp.Status {
		case "approved":
			slog.Info("Enrollment approved!", "id", enrollResp.ID)
			return &EnrollmentResult{
				CertPEM: []byte(enrollResp.CertPEM),
				CAPEM:   []byte(enrollResp.CAPEM),
				ID:      enrollResp.ID,
			}, nil
		case "revoked":
			return nil, fmt.Errorf("enrollment was revoked")
		case "pending":
			slog.Debug("Enrollment still pending", "id", enrollResp.ID)
		default:
			slog.Warn("Unknown enrollment status", "status", enrollResp.Status)
		}

		sleepWithContext(ctx, currentInterval)
		currentInterval = nextBackoff(currentInterval, maxInterval)
	}
}

// nextBackoff doubles the interval up to max.
func nextBackoff(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		return max
	}
	return next
}

// sleepWithContext sleeps for the given duration or until the context is cancelled.
func sleepWithContext(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// EnrollAndWait performs the full enrollment flow:
// 1. Check for cached certificate on disk (renew if expiring within 12h)
// 2. Generate CSR with the key manager's signer
// 3. Submit to cloud (with public key fingerprint)
// 4. Poll until approved (respects context cancellation/timeout)
// 5. Cache certificate to disk
func EnrollAndWait(ctx context.Context, km *KeyManager, cloudURL, caFile, certSHA256, deviceID, hostname, dataDir string) (*EnrollmentResult, error) {
	certPath := filepath.Join(dataDir, "client.crt")
	caPath := filepath.Join(dataDir, "ca.crt")

	// Check for cached certificate
	if certPEM, err := os.ReadFile(certPath); err == nil {
		block, _ := pem.Decode(certPEM)
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil && cert.NotAfter.After(time.Now()) {
				// Proactive renewal: if cert expires within 12 hours, renew now
				if cert.NotAfter.Before(time.Now().Add(12 * time.Hour)) {
					slog.Info("Certificate expires soon, attempting renewal",
						"expires", cert.NotAfter.Format(time.RFC3339))
					result, err := renewCertFlow(km, cloudURL, caFile, certSHA256, deviceID, hostname, certPath, caPath)
					if err == nil {
						return result, nil
					}
					slog.Warn("Renewal failed, using existing cert", "error", err)
				}
				caPEM, _ := os.ReadFile(caPath)
				slog.Info("Using cached enrollment certificate", "path", certPath,
					"expires", cert.NotAfter.Format("2006-01-02"))
				return &EnrollmentResult{CertPEM: certPEM, CAPEM: caPEM, ID: ""}, nil
			}
			slog.Info("Cached certificate expired, re-enrolling")
		}
	}

	// Generate CSR
	csrPEM, err := CreateCSR(km.Signer(), deviceID, hostname)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	// Compute public key fingerprint for first-come binding
	fingerprint, err := PublicKeyFingerprint(km.Public())
	if err != nil {
		return nil, fmt.Errorf("compute key fingerprint: %w", err)
	}
	slog.Info("Generated CSR", "device_id", deviceID, "hostname", hostname, "tpm", km.IsTPM(), "fingerprint", fingerprint)

	// Submit enrollment
	enrollmentID, err := Enroll(cloudURL, caFile, certSHA256, deviceID, hostname, csrPEM, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	slog.Info("Enrollment submitted", "id", enrollmentID, "status", "pending")

	// Poll for approval (context-aware)
	result, err := WaitForApproval(ctx, cloudURL, caFile, certSHA256, deviceID, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("wait for approval: %w", err)
	}

	// Cache to disk with restrictive permissions
	if err := os.WriteFile(certPath, result.CertPEM, 0600); err != nil {
		slog.Warn("Failed to cache certificate", "error", err)
	}
	if len(result.CAPEM) > 0 {
		if err := os.WriteFile(caPath, result.CAPEM, 0600); err != nil {
			slog.Warn("Failed to cache CA certificate", "error", err)
		}
	}

	return result, nil
}

func enrollHTTPClient(caFile, certSHA256 string) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}

	if caFile != "" {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %s: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}
		tlsConfig.RootCAs = pool
	}

	// Certificate pinning: verify server cert SHA-256 fingerprint
	if certSHA256 != "" {
		pinned := strings.ToLower(strings.ReplaceAll(certSHA256, ":", ""))
		tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no server certificate presented")
			}
			h := sha256.Sum256(cs.PeerCertificates[0].Raw)
			got := hex.EncodeToString(h[:])
			if got != pinned {
				return fmt.Errorf("server cert fingerprint mismatch: got %s, want %s", got, pinned)
			}
			return nil
		}
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

// RenewCert submits a CSR to the cloud renewal endpoint and returns the new certificate.
func RenewCert(cloudURL, caFile, certSHA256, deviceID string, csrPEM []byte, pubKeyFingerprint string) (*EnrollmentResult, error) {
	client, err := enrollHTTPClient(caFile, certSHA256)
	if err != nil {
		return nil, err
	}

	reqBody := enrollmentRequest{
		DeviceID:             deviceID,
		Hostname:             "",
		CSRPEM:               string(csrPEM),
		PublicKeyFingerprint: pubKeyFingerprint,
	}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal renewal request: %w", err)
	}

	url := strings.TrimRight(cloudURL, "/") + "/api/enroll/renew"
	resp, err := client.Post(url, "application/json", strings.NewReader(string(bodyJSON)))
	if err != nil {
		return nil, fmt.Errorf("POST /api/enroll/renew: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var enrollResp enrollmentResponse
	if err := json.Unmarshal(body, &enrollResp); err != nil {
		return nil, fmt.Errorf("parse renewal response: %w (body: %s)", err, string(body))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("renewal failed: %s (HTTP %d)", enrollResp.Message, resp.StatusCode)
	}

	return &EnrollmentResult{
		CertPEM: []byte(enrollResp.CertPEM),
		CAPEM:   []byte(enrollResp.CAPEM),
		ID:      enrollResp.ID,
	}, nil
}

// renewCertFlow generates a new CSR and calls RenewCert, then caches the result.
func renewCertFlow(km *KeyManager, cloudURL, caFile, certSHA256, deviceID, hostname, certPath, caPath string) (*EnrollmentResult, error) {
	csrPEM, err := CreateCSR(km.Signer(), deviceID, hostname)
	if err != nil {
		return nil, fmt.Errorf("create CSR for renewal: %w", err)
	}

	fingerprint, err := PublicKeyFingerprint(km.Public())
	if err != nil {
		return nil, fmt.Errorf("compute key fingerprint: %w", err)
	}

	result, err := RenewCert(cloudURL, caFile, certSHA256, deviceID, csrPEM, fingerprint)
	if err != nil {
		return nil, err
	}

	// Cache renewed cert to disk
	if err := os.WriteFile(certPath, result.CertPEM, 0600); err != nil {
		slog.Warn("Failed to cache renewed certificate", "error", err)
	}
	if len(result.CAPEM) > 0 {
		if err := os.WriteFile(caPath, result.CAPEM, 0600); err != nil {
			slog.Warn("Failed to cache CA certificate", "error", err)
		}
	}

	slog.Info("Certificate renewed successfully")
	return result, nil
}

// StartAutoRenewal runs a background goroutine that checks the cached certificate
// and renews it when it expires within 12 hours. This ensures uninterrupted mTLS
// connectivity with short-lived 24h certificates (BeyondCorp model).
func StartAutoRenewal(ctx context.Context, km *KeyManager, cloudURL, caFile, certSHA256, deviceID, hostname, dataDir string) {
	certPath := filepath.Join(dataDir, "client.crt")
	caPath := filepath.Join(dataDir, "ca.crt")

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Auto-renewal stopped")
			return
		case <-ticker.C:
			certPEM, err := os.ReadFile(certPath)
			if err != nil {
				continue
			}
			block, _ := pem.Decode(certPEM)
			if block == nil {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			if cert.NotAfter.Before(time.Now().Add(12 * time.Hour)) {
				slog.Info("Auto-renewal: certificate expires soon, renewing",
					"expires", cert.NotAfter.Format(time.RFC3339))
				_, err := renewCertFlow(km, cloudURL, caFile, certSHA256, deviceID, hostname, certPath, caPath)
				if err != nil {
					slog.Warn("Auto-renewal failed", "error", err)
				}
			}
		}
	}
}
