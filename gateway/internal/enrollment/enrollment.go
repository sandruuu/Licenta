package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"gateway/internal/config"
)

type Result struct {
	Enrolled  bool
	GatewayID string
}

type enrollRequest struct {
	Token  string `json:"token"`
	CSRPEM string `json:"csr_pem"`
	FQDN   string `json:"fqdn"`
	Name   string `json:"name,omitempty"`
}

type enrollResponse struct {
	Status    string `json:"status"`
	GatewayID string `json:"gateway_id"`
	CertPEM   string `json:"cert_pem"`
	CAPEM     string `json:"ca_pem"`
	Message   string `json:"message,omitempty"`
}

func Ensure(ctx context.Context, cfg *config.Config) (*Result, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if hasFile(cfg.MTLSCert) && hasFile(cfg.MTLSKey) {
		return &Result{}, nil
	}
	if strings.TrimSpace(cfg.EnrollmentToken) == "" {
		return &Result{}, nil
	}
	if strings.TrimSpace(cfg.CloudURL) == "" {
		return nil, fmt.Errorf("cloud_url is required for gateway enrollment")
	}

	applyDefaultPaths(cfg)
	privateKey, csrPEM, err := createCSR(firstNonEmpty(cfg.FQDN, "ztna-gateway"))
	if err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal enrollment key: %w", err)
	}
	if err := config.AtomicWriteFile(cfg.MTLSKey, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, fmt.Errorf("write enrollment key: %w", err)
	}
	if cfg.MTLSCSR != "" {
		if err := config.AtomicWriteFile(cfg.MTLSCSR, []byte(csrPEM), 0o600); err != nil {
			return nil, fmt.Errorf("write enrollment CSR: %w", err)
		}
	}

	body, err := json.Marshal(enrollRequest{
		Token:  cfg.EnrollmentToken,
		CSRPEM: csrPEM,
		FQDN:   cfg.FQDN,
		Name:   firstNonEmpty(cfg.FQDN, "ZTNA Gateway"),
	})
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cfg.CloudURL, "/")+"/api/gateway/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")

	client, err := enrollmentHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("send enrollment request: %w", err)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("cloud rejected enrollment: status=%d body=%s", response.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	var result enrollResponse
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return nil, fmt.Errorf("parse enrollment response: %w", err)
	}
	if result.Status != "enrolled" || strings.TrimSpace(result.CertPEM) == "" {
		return nil, fmt.Errorf("enrollment did not return a signed certificate: %s", result.Message)
	}
	if err := config.AtomicWriteFile(cfg.MTLSCert, []byte(result.CertPEM), 0o644); err != nil {
		return nil, fmt.Errorf("write enrollment certificate: %w", err)
	}
	if result.CAPEM != "" && cfg.CloudCA != "" {
		if err := config.AtomicWriteFile(cfg.CloudCA, []byte(result.CAPEM), 0o644); err != nil {
			return nil, fmt.Errorf("write cloud CA: %w", err)
		}
	}

	if cfg.ControlPlane == nil {
		cfg.ControlPlane = &config.ControlPlaneConfig{}
	}
	cfg.ControlPlane.GatewayID = firstNonEmpty(cfg.ControlPlane.GatewayID, result.GatewayID)
	cfg.ControlPlane.CertFile = firstNonEmpty(cfg.ControlPlane.CertFile, cfg.MTLSCert)
	cfg.ControlPlane.KeyFile = firstNonEmpty(cfg.ControlPlane.KeyFile, cfg.MTLSKey)
	cfg.ControlPlane.CAFile = firstNonEmpty(cfg.ControlPlane.CAFile, cfg.CloudCA, cfg.TLSCA)
	cfg.EnrollmentToken = ""
	return &Result{Enrolled: true, GatewayID: result.GatewayID}, nil
}

func applyDefaultPaths(cfg *config.Config) {
	if cfg.MTLSCert == "" {
		cfg.MTLSCert = "certs/gateway-mtls.crt"
	}
	if cfg.MTLSKey == "" {
		cfg.MTLSKey = "certs/gateway-mtls.key"
	}
	if cfg.MTLSCSR == "" {
		cfg.MTLSCSR = "certs/gateway-mtls.csr"
	}
	if cfg.CloudCA == "" {
		cfg.CloudCA = "certs/cloud-ca.crt"
	}
}

func createCSR(commonName string) (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate enrollment key: %w", err)
	}
	request := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		return nil, "", fmt.Errorf("create enrollment CSR: %w", err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), nil
}

func enrollmentHTTPClient(cfg *config.Config) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	caPath := firstNonEmpty(cfg.CloudCA, cfg.TLSCA)
	if caPath != "" && hasFile(caPath) {
		data, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("parse cloud CA %s", caPath)
		}
		tlsConfig.RootCAs = pool
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}, nil
}

func hasFile(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
