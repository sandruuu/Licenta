package pki

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// VaultConfig defines connectivity/authentication for Vault PKI.
type VaultConfig struct {
	URL        string
	Token      string
	PKIPath    string
	CAFile     string
	ServerName string
	Timeout    time.Duration
}

// VaultClient is a minimal Vault PKI API client used by the cloud signer layer.
type VaultClient struct {
	baseURL string
	token   string
	pkiPath string
	client  *http.Client
}

// NewVaultClient builds a Vault PKI client.
func NewVaultClient(cfg VaultConfig) (*VaultClient, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("vault URL is required")
	}
	parsed, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil {
		return nil, fmt.Errorf("parse vault URL: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("vault URL must use http or https")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("vault URL must include host")
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	transport := &http.Transport{}
	if parsed.Scheme == "https" {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
		if strings.TrimSpace(cfg.CAFile) != "" {
			caPEM, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("read vault CA file %q: %w", cfg.CAFile, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return nil, fmt.Errorf("parse vault CA file %q", cfg.CAFile)
			}
			tlsCfg.RootCAs = pool
		}
		if strings.TrimSpace(cfg.ServerName) != "" {
			tlsCfg.ServerName = strings.TrimSpace(cfg.ServerName)
		}
		transport.TLSClientConfig = tlsCfg
	}

	pkiPath := strings.Trim(strings.TrimSpace(cfg.PKIPath), "/")
	if pkiPath == "" {
		pkiPath = "pki_int"
	}

	return &VaultClient{
		baseURL: strings.TrimRight(parsed.String(), "/"),
		token:   strings.TrimSpace(cfg.Token),
		pkiPath: pkiPath,
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
	}, nil
}

// SignCSR signs a PEM CSR via Vault role-based issuance and returns PEM bundle.
func (v *VaultClient) SignCSR(csrPEM []byte, role, ttl string) ([]byte, error) {
	role = strings.TrimSpace(role)
	if role == "" {
		return nil, fmt.Errorf("vault role is required")
	}

	reqBody := map[string]string{
		"csr":    string(csrPEM),
		"format": "pem",
	}
	if strings.TrimSpace(ttl) != "" {
		reqBody["ttl"] = strings.TrimSpace(ttl)
	}

	endpoint := fmt.Sprintf("%s/v1/%s/sign/%s", v.baseURL, v.pkiPath, url.PathEscape(role))
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal vault sign request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create vault sign request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if v.token != "" {
		req.Header.Set("X-Vault-Token", v.token)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault sign request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read vault sign response: %w", err)
	}

	var payload struct {
		Errors []string `json:"errors"`
		Data   struct {
			Certificate string   `json:"certificate"`
			IssuingCA   string   `json:"issuing_ca"`
			CAChain     []string `json:"ca_chain"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return nil, fmt.Errorf("parse vault sign response: %w", err)
	}

	if resp.StatusCode >= 400 {
		if len(payload.Errors) > 0 {
			return nil, fmt.Errorf("vault sign failed: %s", strings.Join(payload.Errors, "; "))
		}
		return nil, fmt.Errorf("vault sign failed with HTTP %d", resp.StatusCode)
	}

	cert := strings.TrimSpace(payload.Data.Certificate)
	if cert == "" {
		return nil, fmt.Errorf("vault returned empty certificate")
	}

	bundleParts := []string{cert}
	if issuing := strings.TrimSpace(payload.Data.IssuingCA); issuing != "" {
		bundleParts = append(bundleParts, issuing)
	}
	for _, ca := range payload.Data.CAChain {
		trimmed := strings.TrimSpace(ca)
		if trimmed != "" {
			bundleParts = append(bundleParts, trimmed)
		}
	}

	var b strings.Builder
	seen := make(map[string]struct{})
	for _, part := range bundleParts {
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		b.WriteString(part)
		if !strings.HasSuffix(part, "\n") {
			b.WriteByte('\n')
		}
	}

	return []byte(b.String()), nil
}

// GetCAPEM returns the current Vault PKI CA certificate chain in PEM format.
func (v *VaultClient) GetCAPEM() ([]byte, error) {
	endpoint := fmt.Sprintf("%s/v1/%s/ca/pem", v.baseURL, v.pkiPath)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create vault CA request: %w", err)
	}
	if v.token != "" {
		req.Header.Set("X-Vault-Token", v.token)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault CA request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read vault CA response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var payload struct {
			Errors []string `json:"errors"`
		}
		if json.Unmarshal(respBody, &payload) == nil && len(payload.Errors) > 0 {
			return nil, fmt.Errorf("vault CA request failed: %s", strings.Join(payload.Errors, "; "))
		}
		return nil, fmt.Errorf("vault CA request failed with HTTP %d", resp.StatusCode)
	}

	trimmed := strings.TrimSpace(string(respBody))
	if strings.Contains(trimmed, "BEGIN CERTIFICATE") {
		if !strings.HasSuffix(trimmed, "\n") {
			trimmed += "\n"
		}
		return []byte(trimmed), nil
	}

	var payload struct {
		Data struct {
			Certificate string `json:"certificate"`
			IssuingCA   string `json:"issuing_ca"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return nil, fmt.Errorf("unexpected vault CA response format")
	}

	cert := strings.TrimSpace(payload.Data.Certificate)
	if cert == "" {
		return nil, fmt.Errorf("vault returned empty CA certificate")
	}
	if issuing := strings.TrimSpace(payload.Data.IssuingCA); issuing != "" && issuing != cert {
		cert += "\n" + issuing
	}
	if !strings.HasSuffix(cert, "\n") {
		cert += "\n"
	}

	return []byte(cert), nil
}

// RevokeCertificate revokes a previously issued certificate in Vault PKI.
// It prefers revocation by PEM certificate. If PEM is unavailable, it falls
// back to serial-based revocation.
func (v *VaultClient) RevokeCertificate(serial string, certPEM []byte) error {
	reqBody := map[string]string{}

	if trimmedCert := strings.TrimSpace(string(certPEM)); trimmedCert != "" {
		reqBody["certificate"] = leafCertificatePEM(trimmedCert)
	} else {
		normalized, err := normalizeVaultSerial(serial)
		if err != nil {
			return err
		}
		reqBody["serial_number"] = normalized
	}

	endpoint := fmt.Sprintf("%s/v1/%s/revoke", v.baseURL, v.pkiPath)
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal vault revoke request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create vault revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if v.token != "" {
		req.Header.Set("X-Vault-Token", v.token)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("vault revoke request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read vault revoke response: %w", err)
	}

	var payload struct {
		Errors []string `json:"errors"`
	}
	_ = json.Unmarshal(respBody, &payload)

	if resp.StatusCode >= 400 {
		if len(payload.Errors) > 0 {
			return fmt.Errorf("vault revoke failed: %s", strings.Join(payload.Errors, "; "))
		}
		return fmt.Errorf("vault revoke failed with HTTP %d", resp.StatusCode)
	}

	return nil
}

func normalizeVaultSerial(serial string) (string, error) {
	trimmed := strings.TrimSpace(strings.ToLower(serial))
	if trimmed == "" {
		return "", fmt.Errorf("serial number is required for revocation")
	}

	// Vault already accepts colon-separated hex serials.
	if strings.Contains(trimmed, ":") {
		return trimmed, nil
	}

	if strings.HasPrefix(trimmed, "0x") {
		trimmed = strings.TrimPrefix(trimmed, "0x")
	}

	hexSerial := ""
	if isDigits(trimmed) {
		bi := new(big.Int)
		if _, ok := bi.SetString(trimmed, 10); !ok {
			return "", fmt.Errorf("invalid decimal serial %q", serial)
		}
		hexSerial = bi.Text(16)
	} else {
		hexSerial = trimmed
	}

	hexSerial = strings.TrimLeft(hexSerial, "0")
	if hexSerial == "" {
		hexSerial = "00"
	}
	if len(hexSerial)%2 != 0 {
		hexSerial = "0" + hexSerial
	}

	parts := make([]string, 0, len(hexSerial)/2)
	for i := 0; i < len(hexSerial); i += 2 {
		parts = append(parts, hexSerial[i:i+2])
	}

	return strings.Join(parts, ":"), nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func leafCertificatePEM(bundle string) string {
	trimmed := strings.TrimSpace(bundle)
	if trimmed == "" {
		return ""
	}

	block, _ := pem.Decode([]byte(trimmed))
	if block == nil || block.Type != "CERTIFICATE" {
		return trimmed
	}

	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
	return strings.TrimSpace(string(leaf))
}
