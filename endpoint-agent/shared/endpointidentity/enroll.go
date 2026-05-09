package endpointidentity

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
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const endpointComponent = "endpoint"

// EnrollmentResult holds the result of a successful endpoint certificate enrollment.
type EnrollmentResult struct {
	CertPEM []byte
	CAPEM   []byte
	ID      string
}

type enrollState struct {
	SessionID string    `json:"session_id"`
	StartedAt time.Time `json:"started_at"`
}

type enrollmentResponse struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	CertPEM string `json:"cert_pem,omitempty"`
	CAPEM   string `json:"ca_pem,omitempty"`
	Message string `json:"message,omitempty"`
}

type enrollmentRequest struct {
	DeviceID             string `json:"device_id"`
	Component            string `json:"component"`
	Hostname             string `json:"hostname"`
	CSRPEM               string `json:"csr_pem"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
}

type startSessionResponse struct {
	SessionID string `json:"session_id"`
	AuthURL   string `json:"auth_url"`
	ExpiresIn int    `json:"expires_in"`
}

type sessionStatusResponse struct {
	Status  string `json:"status"`
	CertPEM string `json:"cert_pem,omitempty"`
	CAPEM   string `json:"ca_pem,omitempty"`
	Message string `json:"message,omitempty"`
}

type TokenEnrollmentConfig struct {
	CloudURL   string
	CAFile     string
	CertSHA256 string
	Token      string
	Nonce      string
	DeviceID   string
	Hostname   string
	UserEmail  string
	DataDir    string
}

type CSRIdentity struct {
	DeviceID  string
	Hostname  string
	UserEmail string
}

type RenewalConfig struct {
	CloudURL             string
	CAFile               string
	CertSHA256           string
	DeviceID             string
	CSRPEM               []byte
	PublicKeyFingerprint string
	CertPEM              []byte
	Signer               crypto.Signer
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

// CreateCSR generates a PEM-encoded CSR signed by the endpoint key.
func CreateCSR(signer crypto.Signer, deviceID, hostname string) ([]byte, error) {
	return CreateCSRWithIdentity(signer, CSRIdentity{DeviceID: deviceID, Hostname: hostname})
}

func CreateCSRWithIdentity(signer crypto.Signer, identity CSRIdentity) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   strings.TrimSpace(identity.DeviceID),
			Organization: []string{"ZeroTrust Endpoint"},
		},
	}
	if strings.TrimSpace(identity.Hostname) != "" {
		template.DNSNames = []string{strings.TrimSpace(identity.Hostname)}
	}
	if email, ok, err := emailSAN(identity.UserEmail); err != nil {
		return nil, err
	} else if ok {
		template.EmailAddresses = []string{email}
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

func emailSAN(value string) (string, bool, error) {
	value = strings.TrimSpace(value)
	if value == "" || !strings.Contains(value, "@") {
		return "", false, nil
	}
	addr, err := mail.ParseAddress(value)
	if err != nil || addr == nil || addr.Name != "" || addr.Address != value {
		return "", false, fmt.Errorf("invalid user email for CSR SAN")
	}
	return addr.Address, true, nil
}

// EnrollAndWait performs the unified endpoint enrollment flow and stores the
// single device certificate in the shared endpoint state directory.
func EnrollAndWait(ctx context.Context, km *KeyManager, cloudURL, caFile, certSHA256, deviceID, hostname, dataDir string) (*EnrollmentResult, error) {
	stateDir := SharedStateDir(cleanFallbackDir(dataDir))
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("create shared endpoint state dir: %w", err)
	}

	certPath := filepath.Join(stateDir, "device.crt")
	caPath := filepath.Join(stateDir, "ca.crt")
	statePath := filepath.Join(stateDir, "enroll-state.json")
	lockPath := filepath.Join(stateDir, "enroll.lock")

	if result, cert, ok := loadCachedCertificate(km, certPath, caPath); ok {
		if cert.NotAfter.Before(time.Now().Add(12 * time.Hour)) {
			slog.Info("Endpoint certificate expires soon, attempting renewal", "expires", cert.NotAfter.Format(time.RFC3339))
			if result, err := renewWithLock(ctx, km, cloudURL, caFile, certSHA256, deviceID, hostname, certPath, caPath, lockPath); err == nil {
				return result, nil
			} else {
				slog.Warn("Endpoint certificate renewal failed, using cached certificate", "error", err)
			}
		}
		slog.Info("Using cached endpoint device certificate", "path", certPath, "expires", cert.NotAfter.Format(time.RFC3339))
		return result, nil
	}

	release, err := acquireEnrollmentLock(ctx, lockPath, func() bool {
		result, _, ok := loadCachedCertificate(km, certPath, caPath)
		_ = result
		return ok
	})
	if err != nil {
		if result, _, ok := loadCachedCertificate(km, certPath, caPath); ok {
			return result, nil
		}
		return nil, err
	}
	defer release()

	if result, cert, ok := loadCachedCertificate(km, certPath, caPath); ok {
		slog.Info("Using endpoint device certificate created by another agent", "path", certPath, "expires", cert.NotAfter.Format(time.RFC3339))
		return result, nil
	}

	if data, err := os.ReadFile(statePath); err == nil {
		var st enrollState
		if json.Unmarshal(data, &st) == nil && st.SessionID != "" && time.Since(st.StartedAt) < 4*time.Minute {
			slog.Info("Resuming pending endpoint enrollment", "session_id", st.SessionID, "age", time.Since(st.StartedAt))
			if result, err := WaitForBrowserAuth(ctx, cloudURL, caFile, certSHA256, st.SessionID, 3*time.Second); err == nil {
				_ = os.Remove(statePath)
				cacheEnrollmentResult(certPath, caPath, result)
				return result, nil
			} else {
				slog.Warn("Pending endpoint enrollment resume failed, starting fresh", "error", err)
				_ = os.Remove(statePath)
			}
		} else {
			_ = os.Remove(statePath)
		}
	}

	csrPEM, err := CreateCSR(km.Signer(), deviceID, hostname)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	fingerprint, err := PublicKeyFingerprint(km.Public())
	if err != nil {
		return nil, fmt.Errorf("compute key fingerprint: %w", err)
	}
	slog.Info("Generated endpoint CSR", "device_id", deviceID, "hostname", hostname, "tpm", km.IsTPM(), "fingerprint", fingerprint)

	session, err := StartEnrollSession(cloudURL, caFile, certSHA256, deviceID, hostname, csrPEM, fingerprint)
	if err != nil {
		if strings.Contains(err.Error(), "HTTP 409") {
			if result, renewErr := renewCertFlow(km, cloudURL, caFile, certSHA256, deviceID, hostname, certPath, caPath); renewErr == nil {
				return result, nil
			}
		}
		return nil, fmt.Errorf("start endpoint enrollment session: %w", err)
	}
	slog.Info("Endpoint enrollment session created, opening browser", "auth_url", session.AuthURL)

	if data, jerr := json.Marshal(enrollState{SessionID: session.SessionID, StartedAt: time.Now()}); jerr == nil {
		_ = os.WriteFile(statePath, data, 0600)
	}

	if err := openBrowser(session.AuthURL); err != nil {
		slog.Warn("Could not open browser automatically", "error", err)
		slog.Info("Open this URL to complete endpoint enrollment", "url", session.AuthURL)
	}

	result, err := WaitForBrowserAuth(ctx, cloudURL, caFile, certSHA256, session.SessionID, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("browser endpoint enrollment: %w", err)
	}
	_ = os.Remove(statePath)
	cacheEnrollmentResult(certPath, caPath, result)
	return result, nil
}

func EnrollWithToken(ctx context.Context, km *KeyManager, config TokenEnrollmentConfig) (*EnrollmentResult, error) {
	if km == nil {
		return nil, fmt.Errorf("endpoint key manager is required")
	}
	config.CloudURL = strings.TrimSpace(config.CloudURL)
	config.Token = strings.TrimSpace(config.Token)
	config.Nonce = strings.TrimSpace(config.Nonce)
	config.DeviceID = strings.TrimSpace(config.DeviceID)
	config.Hostname = strings.TrimSpace(config.Hostname)
	config.UserEmail = strings.TrimSpace(config.UserEmail)
	if config.CloudURL == "" {
		return nil, fmt.Errorf("cloud URL is required")
	}
	if config.Token == "" {
		return nil, fmt.Errorf("bearer token is required")
	}
	if config.DeviceID == "" {
		deviceID, err := km.DeviceFingerprint()
		if err != nil {
			return nil, fmt.Errorf("derive endpoint device id: %w", err)
		}
		config.DeviceID = deviceID
	}

	stateDir := SharedStateDir(cleanFallbackDir(config.DataDir))
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("create shared endpoint state dir: %w", err)
	}
	certPath := filepath.Join(stateDir, "device.crt")
	caPath := filepath.Join(stateDir, "ca.crt")
	lockPath := filepath.Join(stateDir, "enroll.lock")
	if result, cert, ok := loadCachedCertificate(km, certPath, caPath); ok && cert.NotAfter.After(time.Now().Add(12*time.Hour)) {
		return result, nil
	}
	release, err := acquireEnrollmentLock(ctx, lockPath, func() bool {
		_, _, ok := loadCachedCertificate(km, certPath, caPath)
		return ok
	})
	if err != nil {
		return nil, err
	}
	defer release()
	if result, cert, ok := loadCachedCertificate(km, certPath, caPath); ok && cert.NotAfter.After(time.Now().Add(12*time.Hour)) {
		return result, nil
	}

	csrPEM, err := CreateCSRWithIdentity(km.Signer(), CSRIdentity{DeviceID: config.DeviceID, Hostname: config.Hostname, UserEmail: config.UserEmail})
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	fingerprint, err := PublicKeyFingerprint(km.Public())
	if err != nil {
		return nil, fmt.Errorf("compute key fingerprint: %w", err)
	}
	result, err := SimpleEnrollWithToken(ctx, config, csrPEM, fingerprint)
	if err != nil {
		return nil, err
	}
	cacheEnrollmentResult(certPath, caPath, result)
	return result, nil
}

func SimpleEnrollWithToken(ctx context.Context, config TokenEnrollmentConfig, csrPEM []byte, pubKeyFingerprint string) (*EnrollmentResult, error) {
	config.CloudURL = strings.TrimSpace(config.CloudURL)
	config.Token = strings.TrimSpace(config.Token)
	config.Nonce = strings.TrimSpace(config.Nonce)
	config.DeviceID = strings.TrimSpace(config.DeviceID)
	config.Hostname = strings.TrimSpace(config.Hostname)
	config.UserEmail = strings.TrimSpace(config.UserEmail)
	if config.CloudURL == "" {
		return nil, fmt.Errorf("cloud URL is required")
	}
	if config.Token == "" {
		return nil, fmt.Errorf("bearer token is required")
	}
	if config.DeviceID == "" {
		return nil, fmt.Errorf("device id is required")
	}
	if strings.TrimSpace(string(csrPEM)) == "" {
		return nil, fmt.Errorf("CSR is required")
	}

	client, err := enrollHTTPClient(config.CAFile, config.CertSHA256)
	if err != nil {
		return nil, err
	}
	reqBody := enrollmentRequest{
		DeviceID:             config.DeviceID,
		Component:            endpointComponent,
		Hostname:             config.Hostname,
		CSRPEM:               string(csrPEM),
		PublicKeyFingerprint: strings.TrimSpace(pubKeyFingerprint),
	}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal EST enrollment request: %w", err)
	}

	endpoint := strings.TrimRight(config.CloudURL, "/") + "/.well-known/est/ztna/simpleenroll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return nil, fmt.Errorf("build EST enrollment request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+config.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if config.Nonce != "" {
		req.Header.Set("X-ZTNA-Enrollment-Nonce", config.Nonce)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST /.well-known/est/ztna/simpleenroll: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var enrollResp enrollmentResponse
	if len(body) > 0 {
		if err := json.Unmarshal(body, &enrollResp); err != nil {
			return nil, fmt.Errorf("parse EST enrollment response: %w (body: %s)", err, string(body))
		}
	}
	if resp.StatusCode != http.StatusOK {
		message := strings.TrimSpace(enrollResp.Message)
		if message == "" {
			message = strings.TrimSpace(string(body))
		}
		return nil, fmt.Errorf("EST enrollment failed (HTTP %d): %s", resp.StatusCode, message)
	}
	if strings.TrimSpace(enrollResp.CertPEM) == "" {
		return nil, fmt.Errorf("EST enrollment response did not include cert_pem")
	}
	return &EnrollmentResult{CertPEM: []byte(enrollResp.CertPEM), CAPEM: []byte(enrollResp.CAPEM), ID: enrollResp.ID}, nil
}

func StartEnrollSession(cloudURL, caFile, certSHA256, deviceID, hostname string, csrPEM []byte, pubKeyFingerprint string) (*startSessionResponse, error) {
	client, err := enrollHTTPClient(caFile, certSHA256)
	if err != nil {
		return nil, err
	}

	reqBody := enrollmentRequest{
		DeviceID:             deviceID,
		Component:            endpointComponent,
		Hostname:             hostname,
		CSRPEM:               string(csrPEM),
		PublicKeyFingerprint: pubKeyFingerprint,
	}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal enrollment request: %w", err)
	}

	endpoint := strings.TrimRight(cloudURL, "/") + "/api/enroll/start-session"
	resp, err := client.Post(endpoint, "application/json", strings.NewReader(string(bodyJSON)))
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

func WaitForBrowserAuth(ctx context.Context, cloudURL, caFile, certSHA256, sessionID string, pollInterval time.Duration) (*EnrollmentResult, error) {
	client, err := enrollHTTPClient(caFile, certSHA256)
	if err != nil {
		return nil, err
	}

	statusURL := strings.TrimRight(cloudURL, "/") + "/api/enroll/session-status?session=" + url.QueryEscape(sessionID)

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("enrollment cancelled: %w", ctx.Err())
		default:
		}

		slog.Info("Waiting for endpoint browser authentication", "session", shortID(sessionID))

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("enrollment cancelled: %w", ctx.Err())
			}
			slog.Warn("Endpoint enrollment poll failed, retrying", "error", err)
			sleepWithContext(ctx, pollInterval)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var statusResp sessionStatusResponse
		if err := json.Unmarshal(body, &statusResp); err != nil {
			slog.Warn("Invalid endpoint enrollment poll response, retrying", "error", err)
			sleepWithContext(ctx, pollInterval)
			continue
		}

		switch statusResp.Status {
		case "authenticated":
			slog.Info("Endpoint browser authentication complete, certificate issued")
			return &EnrollmentResult{CertPEM: []byte(statusResp.CertPEM), CAPEM: []byte(statusResp.CAPEM), ID: sessionID}, nil
		case "denied":
			return nil, fmt.Errorf("authentication denied: %s", statusResp.Message)
		case "expired":
			return nil, fmt.Errorf("enrollment session expired")
		case "pending":
		default:
			slog.Warn("Unknown endpoint enrollment status", "status", statusResp.Status)
		}

		sleepWithContext(ctx, pollInterval)
	}
}

func RenewCert(cloudURL, caFile, certSHA256, deviceID string, csrPEM []byte, pubKeyFingerprint string) (*EnrollmentResult, error) {
	client, err := enrollHTTPClient(caFile, certSHA256)
	if err != nil {
		return nil, err
	}
	return renewCertWithClient(client, cloudURL, deviceID, csrPEM, pubKeyFingerprint)
}

func RenewCertWithMTLS(config RenewalConfig) (*EnrollmentResult, error) {
	if len(config.CertPEM) == 0 || config.Signer == nil {
		return nil, fmt.Errorf("mTLS renewal requires current certificate and signer")
	}
	client, err := enrollHTTPClientWithCertificate(config.CAFile, config.CertSHA256, config.CertPEM, config.Signer)
	if err != nil {
		return nil, err
	}
	return renewCertWithClient(client, config.CloudURL, config.DeviceID, config.CSRPEM, config.PublicKeyFingerprint)
}

func renewCertWithClient(client *http.Client, cloudURL, deviceID string, csrPEM []byte, pubKeyFingerprint string) (*EnrollmentResult, error) {
	reqBody := enrollmentRequest{
		DeviceID:             deviceID,
		Component:            endpointComponent,
		CSRPEM:               string(csrPEM),
		PublicKeyFingerprint: pubKeyFingerprint,
	}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal renewal request: %w", err)
	}

	endpoint := strings.TrimRight(cloudURL, "/") + "/api/enroll/renew"
	resp, err := client.Post(endpoint, "application/json", strings.NewReader(string(bodyJSON)))
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

	return &EnrollmentResult{CertPEM: []byte(enrollResp.CertPEM), CAPEM: []byte(enrollResp.CAPEM), ID: enrollResp.ID}, nil
}

func StartAutoRenewal(ctx context.Context, km *KeyManager, cloudURL, caFile, certSHA256, deviceID, hostname, dataDir string) {
	stateDir := SharedStateDir(cleanFallbackDir(dataDir))
	certPath := filepath.Join(stateDir, "device.crt")
	caPath := filepath.Join(stateDir, "ca.crt")
	lockPath := filepath.Join(stateDir, "enroll.lock")

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Endpoint certificate auto-renewal stopped")
			return
		case <-ticker.C:
			_, cert, ok := loadCachedCertificate(km, certPath, caPath)
			if !ok || !cert.NotAfter.Before(time.Now().Add(12*time.Hour)) {
				continue
			}
			if _, err := renewWithLock(ctx, km, cloudURL, caFile, certSHA256, deviceID, hostname, certPath, caPath, lockPath); err != nil {
				slog.Warn("Endpoint certificate auto-renewal failed", "error", err)
			}
		}
	}
}

// LoadCertificateFromCache returns the currently valid endpoint certificate
// from the shared transitional cache when it matches the active endpoint key.
func LoadCertificateFromCache(km *KeyManager, dataDir string) (*EnrollmentResult, *x509.Certificate, bool) {
	stateDir := SharedStateDir(cleanFallbackDir(dataDir))
	certPath := filepath.Join(stateDir, "device.crt")
	caPath := filepath.Join(stateDir, "ca.crt")
	return loadCachedCertificate(km, certPath, caPath)
}

// StoreCertificateInCache writes endpoint certificate material to the shared
// transitional cache used during Device-Agent migration.
func StoreCertificateInCache(dataDir string, result *EnrollmentResult) {
	stateDir := SharedStateDir(cleanFallbackDir(dataDir))
	certPath := filepath.Join(stateDir, "device.crt")
	caPath := filepath.Join(stateDir, "ca.crt")
	cacheEnrollmentResult(certPath, caPath, result)
}

func renewWithLock(ctx context.Context, km *KeyManager, cloudURL, caFile, certSHA256, deviceID, hostname, certPath, caPath, lockPath string) (*EnrollmentResult, error) {
	release, err := acquireEnrollmentLock(ctx, lockPath, func() bool { return false })
	if err != nil {
		return nil, err
	}
	defer release()
	return renewCertFlow(km, cloudURL, caFile, certSHA256, deviceID, hostname, certPath, caPath)
}

func renewCertFlow(km *KeyManager, cloudURL, caFile, certSHA256, deviceID, hostname, certPath, caPath string) (*EnrollmentResult, error) {
	csrPEM, err := CreateCSR(km.Signer(), deviceID, hostname)
	if err != nil {
		return nil, fmt.Errorf("create CSR for renewal: %w", err)
	}

	fingerprint, err := PublicKeyFingerprint(km.Public())
	if err != nil {
		return nil, fmt.Errorf("compute key fingerprint: %w", err)
	}

	currentCertPEM, certErr := os.ReadFile(certPath)
	var result *EnrollmentResult
	if certErr == nil && len(currentCertPEM) > 0 {
		result, err = RenewCertWithMTLS(RenewalConfig{
			CloudURL:             cloudURL,
			CAFile:               caFile,
			CertSHA256:           certSHA256,
			DeviceID:             deviceID,
			CSRPEM:               csrPEM,
			PublicKeyFingerprint: fingerprint,
			CertPEM:              currentCertPEM,
			Signer:               km,
		})
	} else {
		result, err = RenewCert(cloudURL, caFile, certSHA256, deviceID, csrPEM, fingerprint)
	}
	if err != nil {
		return nil, err
	}

	cacheEnrollmentResult(certPath, caPath, result)
	slog.Info("Endpoint certificate renewed successfully")
	return result, nil
}

func loadCachedCertificate(km *KeyManager, certPath, caPath string) (*EnrollmentResult, *x509.Certificate, bool) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.NotAfter.After(time.Now()) || time.Now().Before(cert.NotBefore) {
		return nil, nil, false
	}

	certFP, err := PublicKeyFingerprint(cert.PublicKey)
	if err != nil {
		return nil, nil, false
	}
	signerFP, err := PublicKeyFingerprint(km.Public())
	if err != nil {
		return nil, nil, false
	}
	if certFP != signerFP {
		slog.Warn("Cached endpoint certificate key mismatch, re-enrolling", "cert_fp", shortID(certFP), "signer_fp", shortID(signerFP))
		_ = os.Remove(certPath)
		_ = os.Remove(caPath)
		return nil, nil, false
	}

	caPEM, _ := os.ReadFile(caPath)
	return &EnrollmentResult{CertPEM: certPEM, CAPEM: caPEM}, cert, true
}

func cacheEnrollmentResult(certPath, caPath string, result *EnrollmentResult) {
	if result == nil {
		return
	}
	if err := os.WriteFile(certPath, result.CertPEM, 0600); err != nil {
		slog.Warn("Failed to cache endpoint certificate", "error", err)
	}
	if len(result.CAPEM) > 0 {
		if err := os.WriteFile(caPath, result.CAPEM, 0600); err != nil {
			slog.Warn("Failed to cache endpoint CA certificate", "error", err)
		}
	}
}

func acquireEnrollmentLock(ctx context.Context, lockPath string, ready func() bool) (func(), error) {
	for {
		file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			_, _ = fmt.Fprintf(file, "pid=%d\ncreated_at=%s\n", os.Getpid(), time.Now().Format(time.RFC3339))
			_ = file.Close()
			return func() { _ = os.Remove(lockPath) }, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("create endpoint enrollment lock: %w", err)
		}
		if isStaleLock(lockPath, 10*time.Minute) {
			slog.Warn("Removing stale endpoint enrollment lock", "path", lockPath)
			_ = os.Remove(lockPath)
			continue
		}
		if ready != nil && ready() {
			return func() {}, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for endpoint enrollment lock: %w", ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
}

func isStaleLock(lockPath string, maxAge time.Duration) bool {
	info, err := os.Stat(lockPath)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) > maxAge
}

func enrollHTTPClient(caFile, certSHA256 string) (*http.Client, error) {
	return enrollHTTPClientWithCertificate(caFile, certSHA256, nil, nil)
}

func enrollHTTPClientWithCertificate(caFile, certSHA256 string, certPEM []byte, signer crypto.Signer) (*http.Client, error) {
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

	if len(certPEM) > 0 || signer != nil {
		if len(certPEM) == 0 || signer == nil {
			return nil, fmt.Errorf("client certificate and signer must be provided together")
		}
		cert, err := tlsCertificateForSigner(certPEM, signer)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

func tlsCertificateForSigner(certPEM []byte, signer crypto.Signer) (tls.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return tls.Certificate{}, fmt.Errorf("client certificate is not PEM encoded")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse client certificate: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{leaf.Raw},
		PrivateKey:  signer,
		Leaf:        leaf,
	}, nil
}

func openBrowser(rawURL string) error {
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

func sleepWithContext(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func shortID(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12] + "..."
}
