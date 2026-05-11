package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"gateway/internal/config"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/structpb"
)

// CloudClient handles communication with the Cloud control plane.
type CloudClient struct {
	cloudURL string
	client   *http.Client

	pkiURL   string
	pkiPath  string
	pkiToken string

	mu      sync.RWMutex
	breaker *CircuitBreaker
	stopCh  chan struct{}
}

// ConnectRequest asks the gateway to open a data relay to a resource.
type ConnectRequest struct {
	Type         string           `json:"type"`
	RemoteAddr   string           `json:"remote_addr"`
	RemotePort   int              `json:"remote_port"`
	Token        string           `json:"token,omitempty"`
	SessionID    string           `json:"session_id,omitempty"`
	SessionToken string           `json:"session_token,omitempty"`
	ResourceID   string           `json:"resource_id,omitempty"`
	Protocol     string           `json:"protocol,omitempty"`
	DeviceID     string           `json:"device_id,omitempty"`
	Process      *ProcessIdentity `json:"process,omitempty"`
}

// ProcessIdentity carries the local application identity observed by
// connect-app when the TCP flow was intercepted. It is a policy/risk signal,
// not a cryptographic attestation.
type ProcessIdentity struct {
	PID    int    `json:"pid,omitempty"`
	Name   string `json:"name,omitempty"`
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Signer string `json:"signer,omitempty"`
}

// ConnectResponse is sent back to connect-app.
type ConnectResponse struct {
	Type    string `json:"type"`
	Status  string `json:"status"`         // legacy free-form status (kept for back-compat)
	Code    string `json:"code,omitempty"` // structured machine-readable error code
	Message string `json:"message"`
}

// HelloRequest is the first frame a connect-app sends after yamux session
// setup. It announces the wire-protocol version and lets the gateway reject
// clients that are too old / too new before any auth state is allocated.
type HelloRequest struct {
	Type          string   `json:"type"`           // "hello"
	ClientVersion string   `json:"client_version"` // semver, e.g. "1.0"
	ClientApp     string   `json:"client_app"`     // "connect-app"
	ClientBuild   string   `json:"client_build"`   // commit / build id, optional
	Features      []string `json:"features"`       // optional capability flags
}

// HelloResponse is the gateway's reply to a HelloRequest. A non-CodeOK reply
// instructs the client to close the session immediately.
type HelloResponse struct {
	Type             string   `json:"type"` // "hello_ack"
	Code             string   `json:"code"` // CodeOK or CodeBadRequest / CodeInternalError
	ServerVersion    string   `json:"server_version"`
	MinClientVersion string   `json:"min_client_version"`
	MaxClientVersion string   `json:"max_client_version"`
	Features         []string `json:"features"` // gateway-supported capability flags
	Message          string   `json:"message,omitempty"`
}

// Wire-protocol version supported by this build.
const (
	ProtocolVersion          = "1.0"
	ProtocolMinClientVersion = "1.0"
	ProtocolMaxClientVersion = "1.0"
)

// Structured error codes returned to connect-app via the Code field of
// ConnectResponse codes are stable across versions so the client can branch
// on machine-readable identifiers instead of matching free-form messages.
const (
	CodeOK               = "ok"
	CodeAuthInvalid      = "auth_invalid"
	CodeSessionInvalid   = "session_invalid"
	CodeCloudUnreachable = "cloud_unreachable"
	CodeInternalError    = "internal_error"
	CodeBadRequest       = "bad_request"
)

// NewCloudClient creates a new client for cloud communication
func NewCloudClient(cfg *config.Config) (*CloudClient, error) {
	tlsConfig, err := buildCloudTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	client := &CloudClient{
		cloudURL: cfg.CloudURL,
		client:   httpClient,
		pkiURL:   strings.TrimRight(strings.TrimSpace(cfg.PKIURL), "/"),
		pkiPath:  strings.Trim(strings.TrimSpace(cfg.PKIPath), "/"),
		pkiToken: strings.TrimSpace(cfg.PKIToken),
		breaker:  NewCircuitBreaker(),
		stopCh:   make(chan struct{}),
	}
	if client.pkiPath == "" {
		client.pkiPath = "pki_int"
	}

	return client, nil
}

// NewCloudClientInsecure preserves CLI compatibility.
// Strict mTLS is always enforced for gateway-to-cloud communication.
// InsecureSkipVerify is NOT supported — use proper CA configuration instead.
func NewCloudClientInsecure(cfg *config.Config) (*CloudClient, error) {
	log.Printf("[AUTH] WARNING: insecure mode requested but ignored; cloud communication always enforces strict mTLS")
	return NewCloudClient(cfg)
}

func buildCloudTLSConfig(cfg *config.Config) (*tls.Config, error) {
	cloudURL := strings.TrimSpace(cfg.CloudURL)
	if cloudURL == "" {
		return nil, fmt.Errorf("cloud_url is required")
	}
	parsedURL, err := url.Parse(cloudURL)
	if err != nil {
		return nil, fmt.Errorf("parse cloud_url: %w", err)
	}
	if !strings.EqualFold(parsedURL.Scheme, "https") {
		return nil, fmt.Errorf("cloud_url must use https because gateway-to-cloud communication is strictly mTLS")
	}
	if strings.TrimSpace(cfg.MTLSCert) == "" || strings.TrimSpace(cfg.MTLSKey) == "" {
		return nil, fmt.Errorf("strict mTLS requires both mtls_cert and mtls_key for gateway-to-cloud communication")
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	caPath := strings.TrimSpace(cfg.CloudCA)
	if caPath == "" {
		caPath = strings.TrimSpace(cfg.TLSCA)
	}
	if caPath != "" {
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read cloud CA: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse cloud CA")
		}
		tlsConfig.RootCAs = caCertPool
		log.Printf("[AUTH] Cloud client using CA from %s", caPath)
	} else {
		log.Printf("[AUTH] Cloud client using system trust store for server certificate validation")
	}

	cert, err := tls.LoadX509KeyPair(cfg.MTLSCert, cfg.MTLSKey)
	if err != nil {
		return nil, fmt.Errorf("load mTLS client cert: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	// Optional certificate pinning by SHA-256 fingerprint of the cloud's leaf
	// certificate. When configured, this protects against a MITM that holds a
	// valid chain from any trusted CA — only the explicitly-pinned cert is
	// accepted. Configured via `cloud_cert_sha256` (hex, optional colons).
	if pinHex := normalizeFingerprint(cfg.CloudCertSHA256); pinHex != "" {
		expected, err := hex.DecodeString(pinHex)
		if err != nil || len(expected) != 32 {
			return nil, fmt.Errorf("cloud_cert_sha256 must be a 32-byte hex SHA-256 fingerprint (got %d bytes after normalisation)", len(expected))
		}
		tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("cloud presented no certificate")
			}
			leaf := cs.PeerCertificates[0]
			actual := sha256.Sum256(leaf.Raw)
			if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
				return fmt.Errorf("cloud cert pinning mismatch: got %x, want %x", actual[:8], expected[:8])
			}
			return nil
		}
		log.Printf("[AUTH] Cloud cert pinning enabled (sha256=%s…)", pinHex[:16])
	}

	return tlsConfig, nil
}

// normalizeFingerprint strips whitespace and ":" separators from a hex SHA-256
// fingerprint and lowercases it. Returns "" for an empty input.
func normalizeFingerprint(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	return strings.ToLower(s)
}

// cloudPost sends a POST request to the cloud service, wrapped by the circuit breaker.
func (c *CloudClient) cloudPost(path string, payload interface{}) ([]byte, error) {
	return c.breaker.Execute(func() ([]byte, error) {
		return c.doCloudPost(path, payload)
	})
}

// doCloudPost is the raw POST implementation without circuit breaker. It
// retries up to 3 times on transient errors (timeouts, connection refused,
// HTTP 5xx) with exponential backoff (100ms, 200ms, 400ms ±25% jitter).
// Permanent errors (4xx, malformed responses) skip retry.
func (c *CloudClient) doCloudPost(path string, payload interface{}) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	return c.withRetry(func() (int, []byte, error) {
		req, reqErr := http.NewRequest(http.MethodPost, c.cloudURL+path, bytes.NewReader(body))
		if reqErr != nil {
			return 0, nil, fmt.Errorf("create request: %w", reqErr)
		}
		req.Header.Set("Content-Type", "application/json")
		return c.doRequest(req)
	})
}

// cloudGet sends a GET request to the cloud service, wrapped by the circuit breaker.
func (c *CloudClient) cloudGet(path string) ([]byte, error) {
	return c.breaker.Execute(func() ([]byte, error) {
		return c.doCloudGet(path)
	})
}

// doCloudGet is the raw GET implementation without circuit breaker. Same
// retry semantics as doCloudPost.
func (c *CloudClient) doCloudGet(path string) ([]byte, error) {
	return c.withRetry(func() (int, []byte, error) {
		req, reqErr := http.NewRequest(http.MethodGet, c.cloudURL+path, nil)
		if reqErr != nil {
			return 0, nil, fmt.Errorf("create request: %w", reqErr)
		}
		return c.doRequest(req)
	})
}

// doRequest executes a single HTTP request and returns the status code, body,
// and error separately so the retry wrapper can decide whether to retry based
// on the status code (5xx → retry, 4xx → fail-fast).
func (c *CloudClient) doRequest(req *http.Request) (int, []byte, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("cloud request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read response: %w", err)
	}
	return resp.StatusCode, respBody, nil
}

// withRetry executes attempt up to 3 times with exponential backoff on
// transient errors. The attempt returns (status, body, err) so the wrapper
// can distinguish retryable HTTP statuses (502/503/504/408/429) from
// permanent failures (other 4xx/5xx with stable error semantics).
func (c *CloudClient) withRetry(attempt func() (int, []byte, error)) ([]byte, error) {
	const maxAttempts = 3
	baseDelay := 100 * time.Millisecond

	var lastErr error
	for i := 0; i < maxAttempts; i++ {
		if i > 0 {
			delay := baseDelay * time.Duration(1<<uint(i-1))
			// ±25% jitter
			jitter := time.Duration(rand.Int63n(int64(delay) / 2)) //nolint:gosec // non-crypto jitter
			sleepFor := delay - delay/4 + jitter
			select {
			case <-time.After(sleepFor):
			case <-c.stopCh:
				return nil, fmt.Errorf("cloud request cancelled during shutdown")
			}
		}

		status, body, err := attempt()
		if err == nil && status < 400 {
			return body, nil
		}

		// Compose an error that captures status when present.
		current := err
		if current == nil {
			current = fmt.Errorf("cloud returned %d: %s", status, strings.TrimSpace(string(body)))
		}

		if !isTransient(status, err) {
			return nil, current
		}
		lastErr = current
	}
	return nil, fmt.Errorf("cloud request failed after %d attempts: %w", maxAttempts, lastErr)
}

// isTransient reports whether a request should be retried. Network timeouts,
// connection failures, and HTTP 408/429/502/503/504 are considered transient.
// Other 4xx and 5xx responses are permanent and skip retry.
func isTransient(status int, err error) bool {
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return true
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return true
		}
		// Heuristic: dial errors, connection resets, EOF on idle connection.
		msg := err.Error()
		if strings.Contains(msg, "connection refused") ||
			strings.Contains(msg, "connection reset") ||
			strings.Contains(msg, "no such host") ||
			strings.Contains(msg, "EOF") ||
			strings.Contains(msg, "broken pipe") {
			return true
		}
	}
	switch status {
	case http.StatusRequestTimeout, // 408
		http.StatusTooManyRequests,    // 429
		http.StatusBadGateway,         // 502
		http.StatusServiceUnavailable, // 503
		http.StatusGatewayTimeout:     // 504
		return true
	}
	return false
}

// GetCACert fetches the issuer CA certificate PEM exposed by cloud.
// The gateway needs this to verify enrollment client certificates.
func (c *CloudClient) GetCACert() ([]byte, error) {
	resp, err := c.cloudGet("/api/ca/cert")
	if err != nil {
		return nil, fmt.Errorf("get cloud CA cert: %w", err)
	}
	return resp, nil
}

// GetRevokedSerials fetches the list of revoked certificate serials from the cloud
func (c *CloudClient) GetRevokedSerials() ([]string, error) {
	resp, err := c.cloudGet("/api/gateway/revoked-serials")
	if err != nil {
		return nil, fmt.Errorf("get revoked serials: %w", err)
	}

	var result struct {
		RevokedSerials []string `json:"revoked_serials"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("parse revoked serials: %w", err)
	}

	return result.RevokedSerials, nil
}

// GetRevokedSerialsByProvider returns revoked serials from Vault CRL endpoints
// and falls back to the cloud compatibility feed when Vault is unavailable.
func (c *CloudClient) GetRevokedSerialsByProvider() ([]string, string, error) {
	serials, err := c.GetVaultRevokedSerials()
	if err == nil {
		return serials, "vault", nil
	}

	fallback, fallbackErr := c.GetRevokedSerials()
	if fallbackErr != nil {
		return nil, "vault", fmt.Errorf("vault revocation sync failed: %w; cloud fallback failed: %v", err, fallbackErr)
	}

	return fallback, "cloud-fallback", fmt.Errorf("vault revocation sync failed, using cloud fallback: %w", err)
}

// GetVaultRevokedSerials pulls revoked serials from Vault PKI CRL endpoints.
func (c *CloudClient) GetVaultRevokedSerials() ([]string, error) {
	if c.pkiURL == "" {
		return nil, fmt.Errorf("pki_url is required for vault CRL sync")
	}

	endpoints := []string{
		fmt.Sprintf("%s/v1/%s/cert/crl/pem", c.pkiURL, c.pkiPath),
		fmt.Sprintf("%s/v1/%s/crl/pem", c.pkiURL, c.pkiPath),
		fmt.Sprintf("%s/v1/%s/cert/crl", c.pkiURL, c.pkiPath),
		fmt.Sprintf("%s/v1/%s/crl", c.pkiURL, c.pkiPath),
	}

	var errs []string
	for _, endpoint := range endpoints {
		respBody, err := c.fetchVaultCRL(endpoint)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s (%v)", endpoint, err))
			continue
		}

		serials, err := parseVaultRevokedSerials(respBody)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s (%v)", endpoint, err))
			continue
		}

		return dedupeStrings(serials), nil
	}

	if len(errs) == 0 {
		return nil, fmt.Errorf("vault CRL endpoints returned no usable response")
	}

	return nil, fmt.Errorf("vault CRL fetch failed: %s", strings.Join(errs, "; "))
}

func (c *CloudClient) fetchVaultCRL(endpoint string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if c.pkiToken != "" {
		req.Header.Set("X-Vault-Token", c.pkiToken)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	return respBody, nil
}

func parseVaultRevokedSerials(respBody []byte) ([]string, error) {
	der, err := extractCRLDER(respBody)
	if err != nil {
		return nil, err
	}

	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("parse CRL: %w", err)
	}

	serials := make([]string, 0, len(crl.RevokedCertificateEntries)+len(crl.RevokedCertificates))
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber != nil {
			serials = append(serials, entry.SerialNumber.String())
		}
	}
	for _, revoked := range crl.RevokedCertificates {
		if revoked.SerialNumber != nil {
			serials = append(serials, revoked.SerialNumber.String())
		}
	}

	return dedupeStrings(serials), nil
}

func extractCRLDER(respBody []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(respBody)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty CRL response")
	}

	if block, _ := pem.Decode(trimmed); block != nil && strings.Contains(block.Type, "CRL") {
		return block.Bytes, nil
	}

	var payload struct {
		Errors []string `json:"errors"`
		Data   struct {
			CRL         string `json:"crl"`
			Certificate string `json:"certificate"`
		} `json:"data"`
	}
	if err := json.Unmarshal(trimmed, &payload); err == nil {
		if len(payload.Errors) > 0 {
			return nil, fmt.Errorf("vault response errors: %s", strings.Join(payload.Errors, "; "))
		}
		for _, candidate := range []string{payload.Data.CRL, payload.Data.Certificate} {
			candidate = strings.TrimSpace(candidate)
			if candidate == "" {
				continue
			}
			if block, _ := pem.Decode([]byte(candidate)); block != nil && strings.Contains(block.Type, "CRL") {
				return block.Bytes, nil
			}
			if der, ok := decodeBase64CRL(candidate); ok {
				return der, nil
			}
		}
	}

	if der, ok := decodeBase64CRL(string(trimmed)); ok {
		return der, nil
	}

	if _, err := x509.ParseRevocationList(trimmed); err == nil {
		return trimmed, nil
	}

	return nil, fmt.Errorf("unsupported CRL response format")
}

func decodeBase64CRL(value string) ([]byte, bool) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		if _, parseErr := x509.ParseRevocationList(decoded); parseErr == nil {
			return decoded, true
		}
	}

	decoded, err = base64.RawStdEncoding.DecodeString(value)
	if err == nil {
		if _, parseErr := x509.ParseRevocationList(decoded); parseErr == nil {
			return decoded, true
		}
	}

	return nil, false
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}

		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}

	return result
}

// CertRenewalResponse is the response from the gateway enrollment gRPC service.
type CertRenewalResponse struct {
	GatewayID string `json:"gateway_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
	Status    string `json:"status"`
	CertPEM   string `json:"cert_pem"`
	CAPEM     string `json:"ca_pem"`
	Message   string `json:"message"`
}

const gatewayEnrollmentGRPCRenewCert = "/ztna.gateway.v1.GatewayEnrollmentService/RenewCertificate"

// RenewCert sends a CSR to the cloud and receives a fresh signed certificate.
// The mTLS identity is verified server-side, so no gateway_id is needed in the body.
func (c *CloudClient) RenewCert(csrPEM string) (*CertRenewalResponse, error) {
	var response *structpb.Struct
	_, err := c.breaker.Execute(func() ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		request, buildErr := structpb.NewStruct(map[string]interface{}{"csr_pem": csrPEM})
		if buildErr != nil {
			return nil, fmt.Errorf("build renewal request: %w", buildErr)
		}
		var invokeErr error
		response, invokeErr = c.invokeGatewayEnrollmentGRPC(ctx, gatewayEnrollmentGRPCRenewCert, request)
		if invokeErr != nil {
			return nil, invokeErr
		}
		return []byte("ok"), nil
	})
	if err != nil {
		return nil, fmt.Errorf("renew cert: %w", err)
	}

	result := CertRenewalResponse{
		GatewayID: structFieldString(response, "gateway_id"),
		TenantID:  structFieldString(response, "tenant_id"),
		Status:    structFieldString(response, "status"),
		CertPEM:   structFieldString(response, "cert_pem"),
		CAPEM:     structFieldString(response, "ca_pem"),
		Message:   structFieldString(response, "message"),
	}
	if result.Status != "renewed" {
		return nil, fmt.Errorf("renewal failed: %s", result.Message)
	}
	return &result, nil
}

func (c *CloudClient) invokeGatewayEnrollmentGRPC(ctx context.Context, method string, request *structpb.Struct) (*structpb.Struct, error) {
	target, serverName, err := grpcTargetFromCloudURL(c.cloudURL)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := c.grpcTLSConfig(serverName)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.DialContext(ctx, target, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("dial gateway enrollment service: %w", err)
	}
	defer conn.Close()
	response := &structpb.Struct{}
	if err := conn.Invoke(ctx, method, request, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *CloudClient) grpcTLSConfig(defaultServerName string) (*tls.Config, error) {
	transport, ok := c.client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		return nil, fmt.Errorf("cloud client transport does not expose a TLS configuration")
	}
	tlsConfig := transport.TLSClientConfig.Clone()
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = strings.TrimSpace(defaultServerName)
	}
	return tlsConfig, nil
}

func grpcTargetFromCloudURL(rawURL string) (string, string, error) {
	parsedURL, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", "", fmt.Errorf("parse cloud_url: %w", err)
	}
	if !strings.EqualFold(parsedURL.Scheme, "https") {
		return "", "", fmt.Errorf("cloud_url must use https for gateway gRPC")
	}
	host := strings.TrimSpace(parsedURL.Host)
	serverName := strings.TrimSpace(parsedURL.Hostname())
	if host == "" || serverName == "" {
		return "", "", fmt.Errorf("cloud_url must include a host")
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(serverName, "443")
	}
	return host, serverName, nil
}

func structFieldString(value *structpb.Struct, key string) string {
	if value == nil {
		return ""
	}
	field, ok := value.GetFields()[key]
	if !ok || field == nil {
		return ""
	}
	return strings.TrimSpace(field.GetStringValue())
}

// ReloadTLSCert reloads the mTLS client certificate from disk.
// Called after a successful certificate renewal so subsequent requests use the new cert.
func (c *CloudClient) ReloadTLSCert(certPath, keyPath string) error {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("reload mTLS cert: %w", err)
	}
	transport, ok := c.client.Transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("unexpected transport type, cannot reload cert")
	}
	transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	// Force new connections with the new cert
	transport.CloseIdleConnections()
	log.Printf("[AUTH] mTLS certificate reloaded from %s", certPath)
	return nil
}

func (c *CloudClient) Close() {}
