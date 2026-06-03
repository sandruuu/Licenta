package enrollment

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	pdptransport "agent/internal/service/pdp-transport"
)

const renewalPath = "/api/enroll/renew"

type HTTPRenewalClient struct {
	config Config
}

func NewHTTPRenewalClient(config Config) *HTTPRenewalClient {
	config = normalizeConfig(config)
	return &HTTPRenewalClient{config: config}
}

func (client *HTTPRenewalClient) RenewCertificate(ctx context.Context, record EnrollmentRecord, certificate tls.Certificate, request CertificateRenewalRequest) (CertificateRenewalResponse, error) {
	if client == nil {
		return CertificateRenewalResponse{}, fmt.Errorf("certificate renewal client is not configured")
	}
	if strings.TrimSpace(request.DeviceID) == "" {
		request.DeviceID = record.DeviceID
	}
	endpoint, err := pdptransport.Endpoint(client.config.PDPGRPCEndpoint, "certificate renewal")
	if err != nil {
		return CertificateRenewalResponse{}, err
	}
	renewURL, err := endpointURL(endpoint, renewalPath)
	if err != nil {
		return CertificateRenewalResponse{}, err
	}
	tlsConfig, err := pdptransport.NewTLSConfig(pdptransport.Config{
		ServerName:   client.config.PDPTLSServerName,
		CAFile:       client.config.PDPCAFile,
		Certificates: []tls.Certificate{certificate},
	})
	if err != nil {
		return CertificateRenewalResponse{}, err
	}

	payload, err := json.Marshal(map[string]string{
		"device_id":              strings.TrimSpace(request.DeviceID),
		"component":              strings.TrimSpace(request.Component),
		"hostname":               strings.TrimSpace(request.Hostname),
		"csr_pem":                strings.TrimSpace(request.CSRPEM),
		"public_key_fingerprint": strings.TrimSpace(request.PublicKeyFingerprint),
	})
	if err != nil {
		return CertificateRenewalResponse{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, renewURL, bytes.NewReader(payload))
	if err != nil {
		return CertificateRenewalResponse{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")

	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	response, err := httpClient.Do(httpRequest)
	if err != nil {
		return CertificateRenewalResponse{}, fmt.Errorf("renew device certificate: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return CertificateRenewalResponse{}, fmt.Errorf("read renewal response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return CertificateRenewalResponse{}, fmt.Errorf("renew device certificate: PDP returned %s: %s", response.Status, renewalErrorMessage(body))
	}

	var decoded struct {
		CertificatePEM        string `json:"certificate_pem"`
		CertPEM               string `json:"cert_pem"`
		CertificateChainPEM   string `json:"certificate_chain_pem"`
		CAPEM                 string `json:"ca_pem"`
		CertificateThumbprint string `json:"certificate_thumbprint"`
		ExpiresAt             string `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return CertificateRenewalResponse{}, fmt.Errorf("decode renewal response: %w", err)
	}
	result := CertificateRenewalResponse{
		CertificatePEM:        firstNonEmpty(decoded.CertificatePEM, decoded.CertPEM),
		CertificateChainPEM:   firstNonEmpty(decoded.CertificateChainPEM, decoded.CAPEM),
		CertificateThumbprint: decoded.CertificateThumbprint,
	}
	if strings.TrimSpace(decoded.ExpiresAt) != "" {
		if expiresAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(decoded.ExpiresAt)); err == nil {
			result.ExpiresAt = expiresAt.UTC()
		}
	}
	if strings.TrimSpace(result.CertificatePEM) == "" {
		return CertificateRenewalResponse{}, fmt.Errorf("renewal response did not include a certificate")
	}
	return result, nil
}

func endpointURL(endpoint, path string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("PDP endpoint is required")
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse PDP endpoint: %w", err)
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("PDP endpoint must use https for certificate renewal")
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return "", fmt.Errorf("PDP endpoint host is required")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + path
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func renewalErrorMessage(body []byte) string {
	var decoded struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &decoded); err == nil {
		if value := firstNonEmpty(decoded.Error, decoded.Message); value != "" {
			return value
		}
	}
	return strings.TrimSpace(string(body))
}
