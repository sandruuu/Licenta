package auth

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"gateway/internal/config"
)

// CloudClient communicates with the ZTNA Cloud service (PA + PE + IdP)
// to authenticate users and authorize access requests
type CloudClient struct {
	cloudURL string
	client   *http.Client
	pkiURL   string
	pkiPath  string
	pkiToken string
	mu       sync.RWMutex
	// Local cache of validated sessions to reduce cloud calls
	sessionCache map[string]*CachedSession
	// Circuit breaker for graceful degradation when cloud is unreachable
	breaker *CircuitBreaker
	// stopCh signals background goroutines to exit during graceful shutdown
	stopCh chan struct{}
}

// CloudResource mirrors the cloud's GatewayResourceSync model.
type CloudResource struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	AllowedRoles []string `json:"allowed_roles,omitempty"`
	RequireMFA   bool     `json:"require_mfa"`
	Enabled      bool     `json:"enabled"`
}

// CachedSession stores a locally cached session validation result
type CachedSession struct {
	SessionID  string
	UserID     string
	Username   string
	Resource   string
	ValidUntil time.Time
}

// AuthRequest is the payload sent from connect-app for authentication
type AuthRequest struct {
	Type      string `json:"type"`
	Token     string `json:"token"`
	DeviceID  string `json:"device_id"`
	Hostname  string `json:"hostname"`
	Timestamp int64  `json:"timestamp"`
}

// AuthResponse is sent back to connect-app after authentication
type AuthResponse struct {
	Type     string   `json:"type"`
	Status   string   `json:"status"` // "authorized", "denied", "mfa_required"
	Message  string   `json:"message"`
	Policies []string `json:"policies"`
}

// ConnectRequest is sent by connect-app to access a specific resource
type ConnectRequest struct {
	Type       string `json:"type"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
}

// ConnectResponse is sent back to connect-app
type ConnectResponse struct {
	Type    string `json:"type"`
	Status  string `json:"status"` // "connected", "denied", "error"
	Message string `json:"message"`
}

// DNSResolveRequest is sent by connect-app over the yamux tunnel to resolve
// an internal domain name to a CGNAT tunnel IP. This replaces static DNS
// mappings — the gateway dynamically allocates a CGNAT IP on demand.
type DNSResolveRequest struct {
	Type   string `json:"type"`   // "dns_resolve"
	Domain string `json:"domain"` // e.g. "bob.external.lab.local"
}

// DNSResolveResponse is sent back to connect-app with the allocated CGNAT IP
type DNSResolveResponse struct {
	Type    string `json:"type"`   // "dns_resolve_response"
	Status  string `json:"status"` // "resolved", "not_found", "error"
	Domain  string `json:"domain"`
	CGNATIP string `json:"cgnat_ip,omitempty"` // allocated CGNAT address
	TTL     int    `json:"ttl,omitempty"`      // seconds until the mapping expires
	Message string `json:"message,omitempty"`
}

// TunnelPacket wraps a raw IP packet sent by connect-app through the yamux
// tunnel. The gateway decapsulates it and forwards it to the internal host
// after performing DNAT (CGNAT IP → internal IP).
type TunnelPacket struct {
	Type string `json:"type"` // "tunnel_data"
	Data []byte `json:"data"` // raw IP packet
}

// AccessDecision mirrors the cloud's access decision
type AccessDecision struct {
	Decision    string   `json:"decision"`
	Reason      string   `json:"reason"`
	RiskScore   int      `json:"risk_score"`
	MatchedRule string   `json:"matched_rule"`
	Policies    []string `json:"policies"`
	SessionID   string   `json:"session_id"`
	ExpiresAt   int64    `json:"expires_at"`
}

// DeviceHealthReport for forwarding to cloud
type DeviceHealthReport struct {
	DeviceID     string        `json:"device_id"`
	Hostname     string        `json:"hostname"`
	OS           string        `json:"os"`
	Checks       []HealthCheck `json:"checks"`
	OverallScore int           `json:"overall_score"`
	ReportedAt   time.Time     `json:"reported_at"`
}

// HealthCheck is a single device health check
type HealthCheck struct {
	Name        string            `json:"name"`
	Status      string            `json:"status"`
	Description string            `json:"description"`
	Details     map[string]string `json:"details"`
}

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
		cloudURL:     cfg.CloudURL,
		client:       httpClient,
		pkiURL:       strings.TrimRight(strings.TrimSpace(cfg.PKIURL), "/"),
		pkiPath:      strings.Trim(strings.TrimSpace(cfg.PKIPath), "/"),
		pkiToken:     strings.TrimSpace(cfg.PKIToken),
		sessionCache: make(map[string]*CachedSession),
		breaker:      NewCircuitBreaker(),
		stopCh:       make(chan struct{}),
	}
	if client.pkiPath == "" {
		client.pkiPath = "pki_int"
	}

	// Background session cache cleanup to prevent unbounded memory growth
	go client.startCacheCleanup()

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

	return tlsConfig, nil
}

// ValidateToken asks the cloud to validate a JWT auth token
func (c *CloudClient) ValidateToken(token string) (map[string]interface{}, error) {
	body := map[string]string{"token": token}
	resp, err := c.cloudPost("/api/gateway/validate-token", body)
	if err != nil {
		return nil, fmt.Errorf("validate token: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if valid, ok := result["valid"].(bool); !ok || !valid {
		errMsg := "token validation failed"
		if e, ok := result["error"].(string); ok {
			errMsg = e
		}
		return nil, fmt.Errorf("%s", errMsg)
	}

	return result, nil
}

// AuthorizeAccess asks the cloud to evaluate an access request
func (c *CloudClient) AuthorizeAccess(userID, username, deviceID, sourceIP, resource string, port int, protocol, authToken, appID string, anomalyAlerts []string, anomalyScore int) (*AccessDecision, error) {
	reqBody := map[string]interface{}{
		"user_id":        userID,
		"username":       username,
		"device_id":      deviceID,
		"source_ip":      sourceIP,
		"resource":       resource,
		"resource_port":  port,
		"protocol":       protocol,
		"auth_token":     authToken,
		"app_id":         appID,
		"anomaly_alerts": anomalyAlerts,
		"anomaly_score":  anomalyScore,
	}

	resp, err := c.cloudPost("/api/gateway/authorize", reqBody)
	if err != nil {
		return nil, fmt.Errorf("authorize access: %w", err)
	}

	var decision AccessDecision
	if err := json.Unmarshal(resp, &decision); err != nil {
		return nil, fmt.Errorf("parse decision: %w", err)
	}

	// Cache the session if access was granted
	if decision.Decision == "allow" && decision.SessionID != "" {
		c.cacheSession(decision.SessionID, userID, username, resource, decision.ExpiresAt)
	}

	return &decision, nil
}

// ReportDeviceHealth forwards a device health report to the cloud
func (c *CloudClient) ReportDeviceHealth(report *DeviceHealthReport) error {
	_, err := c.cloudPost("/api/gateway/device-report", report)
	if err != nil {
		return fmt.Errorf("report device health: %w", err)
	}
	log.Printf("[AUTH] Device health report forwarded to cloud for device %s", report.DeviceID)
	return nil
}

// ValidateSession checks if a session is valid (local cache first, then cloud).
// When the circuit breaker is open, falls back to cached sessions for resilience.
func (c *CloudClient) ValidateSession(sessionID string) (*CachedSession, error) {
	// Check local cache first
	c.mu.RLock()
	cached, ok := c.sessionCache[sessionID]
	c.mu.RUnlock()

	if ok && cached.ValidUntil.After(time.Now()) {
		return cached, nil
	}

	// Cache miss or expired — validate with cloud
	resp, err := c.cloudPost("/api/gateway/session-validate", map[string]string{
		"session_id": sessionID,
	})
	if err != nil {
		// If circuit is open and we have a stale cache entry, use it as fallback
		// but only if the entry is less than 5 minutes stale (max staleness bound)
		if err == ErrCircuitOpen && cached != nil {
			staleness := time.Since(cached.ValidUntil)
			if staleness < 5*time.Minute {
				log.Printf("[AUTH] Circuit open — using stale cached session for %s (stale %s)", sessionID, staleness.Round(time.Second))
				return cached, nil
			}
			log.Printf("[AUTH] Circuit open — rejecting stale cached session for %s (stale %s exceeds 5min limit)", sessionID, staleness.Round(time.Second))
			return nil, fmt.Errorf("session cache expired beyond staleness limit")
		}
		return nil, fmt.Errorf("validate session: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if valid, ok := result["valid"].(bool); !ok || !valid {
		return nil, fmt.Errorf("session is no longer valid")
	}

	return cached, nil
}

// cloudPost sends a POST request to the cloud service, wrapped by the circuit breaker.
func (c *CloudClient) cloudPost(path string, payload interface{}) ([]byte, error) {
	return c.breaker.Execute(func() ([]byte, error) {
		return c.doCloudPost(path, payload)
	})
}

// doCloudPost is the raw POST implementation without circuit breaker.
func (c *CloudClient) doCloudPost(path string, payload interface{}) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.cloudURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloud request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("cloud returned %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// cloudGet sends a GET request to the cloud service, wrapped by the circuit breaker.
func (c *CloudClient) cloudGet(path string) ([]byte, error) {
	return c.breaker.Execute(func() ([]byte, error) {
		return c.doCloudGet(path)
	})
}

// doCloudGet is the raw GET implementation without circuit breaker.
func (c *CloudClient) doCloudGet(path string) ([]byte, error) {
	req, err := http.NewRequest("GET", c.cloudURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloud request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("cloud returned %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
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

// GetResources fetches the gateway's assigned resources from the cloud.
// The cloud identifies the gateway from its mTLS certificate CN.
func (c *CloudClient) GetResources() ([]CloudResource, error) {
	resp, err := c.cloudGet("/api/gateway/resources")
	if err != nil {
		return nil, fmt.Errorf("get resources: %w", err)
	}

	var result struct {
		Resources []CloudResource `json:"resources"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("parse resources: %w", err)
	}

	return result.Resources, nil
}

// CertRenewalResponse is the response from POST /api/gateway/renew-cert
type CertRenewalResponse struct {
	Status  string `json:"status"`
	CertPEM string `json:"cert_pem"`
	CAPEM   string `json:"ca_pem"`
	Message string `json:"message"`
}

// RenewCert sends a CSR to the cloud and receives a fresh signed certificate.
// The mTLS identity is verified server-side — no gateway_id is needed in the body.
func (c *CloudClient) RenewCert(csrPEM string) (*CertRenewalResponse, error) {
	resp, err := c.cloudPost("/api/gateway/renew-cert", map[string]string{
		"csr_pem": csrPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("renew cert: %w", err)
	}

	var result CertRenewalResponse
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("parse renewal response: %w", err)
	}
	if result.Status != "renewed" {
		return nil, fmt.Errorf("renewal failed: %s", result.Message)
	}
	return &result, nil
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

// cacheSession stores a validated session in the local cache.
// The cache TTL is capped at 15 minutes to prevent stale sessions from
// persisting when the cloud is unreachable.
func (c *CloudClient) cacheSession(sessionID, userID, username, resource string, expiresAt int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	validUntil := time.Unix(expiresAt, 0)
	maxCacheTTL := time.Now().Add(15 * time.Minute)
	if validUntil.After(maxCacheTTL) {
		validUntil = maxCacheTTL
	}

	c.sessionCache[sessionID] = &CachedSession{
		SessionID:  sessionID,
		UserID:     userID,
		Username:   username,
		Resource:   resource,
		ValidUntil: validUntil,
	}
}

// CleanExpiredCache removes expired entries from the session cache.
func (c *CloudClient) CleanExpiredCache() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0
	for id, sess := range c.sessionCache {
		if sess.ValidUntil.Before(now) {
			delete(c.sessionCache, id)
			removed++
		}
	}
	return removed
}

// startCacheCleanup periodically removes expired session cache entries.
func (c *CloudClient) startCacheCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if n := c.CleanExpiredCache(); n > 0 {
				log.Printf("[AUTH] Cleaned %d expired session cache entries", n)
			}
		case <-c.stopCh:
			return
		}
	}
}

// Close signals background goroutines to stop.
func (c *CloudClient) Close() {
	close(c.stopCh)
}

// FlushSessionCache removes all entries from the session cache.
// Called when the gateway's own certificate may have been revoked (e.g. 403 from cloud).
func (c *CloudClient) FlushSessionCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id := range c.sessionCache {
		delete(c.sessionCache, id)
	}
	log.Printf("[AUTH] Session cache flushed")
}

// ──────────────────────────────────────────────────────────────────────
// OIDC Token Exchange — Gateway as Relying Party
// ──────────────────────────────────────────────────────────────────────

// OIDCTokenResponse is the response from the Cloud's /auth/token endpoint
type OIDCTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Nonce        string `json:"nonce,omitempty"` // OIDC nonce echo for replay validation
	UserID       string `json:"user_id"`
	Username     string `json:"username"`
	Role         string `json:"role"`
}

// ExchangeCodeForToken exchanges an OIDC authorization code for tokens.
// This is the backend-to-backend call from Gateway to Cloud (Relying Party → IdP).
// The code was obtained via the browser redirect flow.
func (c *CloudClient) ExchangeCodeForToken(tokenURL, clientID, clientSecret, code, redirectURI, codeVerifier string) (*OIDCTokenResponse, error) {
	reqBody := map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  redirectURI,
		"code_verifier": codeVerifier,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal token request: %w", err)
	}

	req, err := http.NewRequest("POST", tokenURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	log.Printf("[AUTH] OIDC token exchange: POST %s (client=%s)", tokenURL, clientID)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("token exchange failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var tokenResp OIDCTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("empty access_token in token response")
	}

	log.Printf("[AUTH] OIDC token exchange successful: user=%s", tokenResp.Username)
	return &tokenResp, nil
}

// RefreshAccessToken uses a refresh token to obtain a new access token and
// a rotated refresh token from the Cloud's /auth/token endpoint.
func (c *CloudClient) RefreshAccessToken(tokenURL, clientID, clientSecret, refreshToken string) (*OIDCTokenResponse, error) {
	reqBody := map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal refresh request: %w", err)
	}

	req, err := http.NewRequest("POST", tokenURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh token request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read refresh response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("refresh failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var tokenResp OIDCTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("parse refresh response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("empty access_token in refresh response")
	}

	log.Printf("[AUTH] Token refresh successful: user=%s", tokenResp.Username)
	return &tokenResp, nil
}
