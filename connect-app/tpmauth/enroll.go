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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// startSessionResponse holds the response from /api/enroll/start-session.
type startSessionResponse struct {
	SessionID string `json:"session_id"`
	AuthURL   string `json:"auth_url"`
	ExpiresIn int    `json:"expires_in"`
}

// sessionStatusResponse holds the response from /api/enroll/session-status.
type sessionStatusResponse struct {
	Status  string `json:"status"`
	CertPEM string `json:"cert_pem,omitempty"`
	CAPEM   string `json:"ca_pem,omitempty"`
	Message string `json:"message,omitempty"`
}

// StartEnrollSession submits a CSR to the cloud and gets a browser auth URL.
// The user must authenticate in their browser to complete enrollment.
func StartEnrollSession(cloudURL, caFile, certSHA256, deviceID, hostname string, csrPEM []byte, pubKeyFingerprint string) (*startSessionResponse, error) {
	client, err := enrollHTTPClient(caFile, certSHA256)
	if err != nil {
		return nil, err
	}

	reqBody := enrollmentRequest{
		DeviceID:             deviceID,
		Component:            "tunnel",
		Hostname:             hostname,
		CSRPEM:               string(csrPEM),
		PublicKeyFingerprint: pubKeyFingerprint,
	}
	bodyJSON, _ := json.Marshal(reqBody)

	url := strings.TrimRight(cloudURL, "/") + "/api/enroll/start-session"
	resp, err := client.Post(url, "application/json", strings.NewReader(string(bodyJSON)))
	if err != nil {
		return nil, fmt.Errorf("POST /api/enroll/start-session: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("start-session failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var result startSessionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w (body: %s)", err, string(body))
	}

	return &result, nil
}

// WaitForBrowserAuth polls the enrollment session status until the user
// authenticates in the browser and the certificate is issued.
func WaitForBrowserAuth(ctx context.Context, cloudURL, caFile, certSHA256, sessionID string, pollInterval time.Duration) (*EnrollmentResult, error) {
	client, err := enrollHTTPClient(caFile, certSHA256)
	if err != nil {
		return nil, err
	}

	statusURL := strings.TrimRight(cloudURL, "/") + "/api/enroll/session-status?session=" + sessionID

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("enrollment cancelled: %w", ctx.Err())
		default:
		}

		slog.Info("Waiting for browser authentication...", "session", sessionID[:12]+"...")

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("enrollment cancelled: %w", ctx.Err())
			}
			slog.Warn("Session poll failed, retrying", "error", err)
			sleepWithContext(ctx, pollInterval)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var statusResp sessionStatusResponse
		if err := json.Unmarshal(body, &statusResp); err != nil {
			slog.Warn("Invalid poll response, retrying", "error", err)
			sleepWithContext(ctx, pollInterval)
			continue
		}

		switch statusResp.Status {
		case "authenticated":
			slog.Info("Browser authentication complete — certificate issued!")
			return &EnrollmentResult{
				CertPEM: []byte(statusResp.CertPEM),
				CAPEM:   []byte(statusResp.CAPEM),
				ID:      sessionID,
			}, nil
		case "denied":
			return nil, fmt.Errorf("authentication denied: %s", statusResp.Message)
		case "expired":
			return nil, fmt.Errorf("enrollment session expired")
		case "pending":
			// Still waiting for user to authenticate in browser
		default:
			slog.Warn("Unknown session status", "status", statusResp.Status)
		}

		sleepWithContext(ctx, pollInterval)
	}
}

// openBrowser opens a URL in the user's default browser.
// Only https:// URLs are allowed to prevent command injection.
func openBrowser(rawURL string) error {
	// Validate URL format to prevent injection
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("only http/https URLs are allowed, got %q", parsed.Scheme)
	}
	safeURL := parsed.String()

	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", safeURL).Start()
	case "darwin":
		return exec.Command("open", safeURL).Start()
	default:
		return exec.Command("xdg-open", safeURL).Start()
	}
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
// 3. Start browser enrollment session on cloud
// 4. Open browser for user to authenticate (OIDC login)
// 5. Poll until certificate is issued (auto-approved after login)
// 6. Cache certificate to disk
func EnrollAndWait(ctx context.Context, km *KeyManager, cloudURL, caFile, certSHA256, deviceID, hostname, dataDir string) (*EnrollmentResult, error) {
	certPath := filepath.Join(dataDir, "client.crt")
	caPath := filepath.Join(dataDir, "ca.crt")

	// Check for cached certificate
	if certPEM, err := os.ReadFile(certPath); err == nil {
		// Verify cert is still valid and matches our current key
		block, _ := pem.Decode(certPEM)
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil && cert.NotAfter.After(time.Now()) {
				// Verify the cert's public key matches the current signer
				certFP, _ := PublicKeyFingerprint(cert.PublicKey)
				signerFP, _ := PublicKeyFingerprint(km.Public())
				if certFP != signerFP {
					slog.Warn("Cached certificate key mismatch — re-enrolling",
						"cert_fp", certFP[:16]+"...", "signer_fp", signerFP[:16]+"...")
					// Remove stale cert files so fresh enrollment can proceed
					os.Remove(certPath)
					os.Remove(caPath)
				} else {
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
			} else {
				slog.Info("Cached certificate expired, re-enrolling")
			}
		}
	}

	// Generate CSR
	csrPEM, err := CreateCSR(km.Signer(), deviceID, hostname)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	// Compute public key fingerprint
	fingerprint, err := PublicKeyFingerprint(km.Public())
	if err != nil {
		return nil, fmt.Errorf("compute key fingerprint: %w", err)
	}
	slog.Info("Generated CSR", "device_id", deviceID, "hostname", hostname, "tpm", km.IsTPM(), "fingerprint", fingerprint)

	// Start browser enrollment session
	session, err := StartEnrollSession(cloudURL, caFile, certSHA256, deviceID, hostname, csrPEM, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("start enrollment session: %w", err)
	}
	slog.Info("Enrollment session created — opening browser for authentication", "auth_url", session.AuthURL)

	// Open browser for user to authenticate
	if err := openBrowser(session.AuthURL); err != nil {
		slog.Warn("Could not open browser automatically", "error", err)
		slog.Info("Please open this URL manually to complete enrollment:", "url", session.AuthURL)
	}

	// Poll for browser authentication completion (5-min session TTL)
	result, err := WaitForBrowserAuth(ctx, cloudURL, caFile, certSHA256, session.SessionID, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("browser enrollment: %w", err)
	}

	// Cache to disk
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
	bodyJSON, _ := json.Marshal(reqBody)

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
