package enrollment

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type RenewalConfig struct {
	CloudURL             string
	CAFile               string
	DeviceID             string
	Hostname             string
	CSRPEM               []byte
	PublicKeyFingerprint string
	CurrentCertificate   tls.Certificate
}

func RenewWithMTLS(ctx context.Context, config RenewalConfig) (*ESTResult, error) {
	config.CloudURL = strings.TrimRight(strings.TrimSpace(config.CloudURL), "/")
	config.DeviceID = strings.TrimSpace(config.DeviceID)
	config.Hostname = strings.TrimSpace(config.Hostname)
	if config.CloudURL == "" {
		return nil, fmt.Errorf("cloud URL is required")
	}
	if config.DeviceID == "" {
		return nil, fmt.Errorf("device_id is required")
	}
	if strings.TrimSpace(string(config.CSRPEM)) == "" {
		return nil, fmt.Errorf("CSR is required")
	}
	client, err := buildHTTPClientWithCertificate(config.CAFile, config.CurrentCertificate)
	if err != nil {
		return nil, err
	}
	return renewWithClient(ctx, client, config.CloudURL, config.DeviceID, config.Hostname, config.CSRPEM, config.PublicKeyFingerprint)
}

func renewWithClient(ctx context.Context, client *http.Client, cloudURL, deviceID, hostname string, csrPEM []byte, publicKeyFingerprint string) (*ESTResult, error) {
	if client == nil {
		return nil, fmt.Errorf("HTTP client is required")
	}
	requestBody := estEnrollmentRequest{
		DeviceID:             strings.TrimSpace(deviceID),
		Component:            endpointComponent,
		Hostname:             strings.TrimSpace(hostname),
		CSRPEM:               string(csrPEM),
		PublicKeyFingerprint: strings.TrimSpace(publicKeyFingerprint),
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("marshal renewal request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cloudURL, "/")+"/api/enroll/renew", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build renewal request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("POST /api/enroll/renew: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read renewal response: %w", err)
	}
	var enrollmentResponse estEnrollmentResponse
	if len(responseBody) > 0 {
		if err := json.Unmarshal(responseBody, &enrollmentResponse); err != nil {
			return nil, fmt.Errorf("parse renewal response: %w", err)
		}
	}
	if response.StatusCode != http.StatusOK {
		message := strings.TrimSpace(enrollmentResponse.Message)
		if message == "" {
			message = strings.TrimSpace(string(responseBody))
		}
		return nil, fmt.Errorf("renewal failed (HTTP %d): %s", response.StatusCode, message)
	}
	if strings.TrimSpace(enrollmentResponse.CertPEM) == "" {
		return nil, fmt.Errorf("renewal response did not include cert_pem")
	}
	return &ESTResult{
		ID:      strings.TrimSpace(enrollmentResponse.ID),
		CertPEM: []byte(enrollmentResponse.CertPEM),
		CAPEM:   []byte(enrollmentResponse.CAPEM),
	}, nil
}
