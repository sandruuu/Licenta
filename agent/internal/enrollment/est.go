package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const endpointComponent = "endpoint"

type TokenEnrollmentConfig struct {
	CloudURL   string
	CAFile     string
	Token      string
	Nonce      string
	DeviceID   string
	Hostname   string
	HTTPClient *http.Client
}

type ESTResult struct {
	ID      string
	CertPEM []byte
	CAPEM   []byte
}

type estEnrollmentRequest struct {
	DeviceID             string `json:"device_id"`
	Component            string `json:"component"`
	Hostname             string `json:"hostname,omitempty"`
	CSRPEM               string `json:"csr_pem"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
}

type estEnrollmentResponse struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	CertPEM string `json:"cert_pem,omitempty"`
	CAPEM   string `json:"ca_pem,omitempty"`
	Message string `json:"message,omitempty"`
}

func SimpleEnrollWithToken(ctx context.Context, config TokenEnrollmentConfig, csrPEM []byte, publicKeyFingerprint string) (*ESTResult, error) {
	config.CloudURL = strings.TrimRight(strings.TrimSpace(config.CloudURL), "/")
	config.Token = strings.TrimSpace(config.Token)
	config.Nonce = strings.TrimSpace(config.Nonce)
	config.DeviceID = strings.TrimSpace(config.DeviceID)
	config.Hostname = strings.TrimSpace(config.Hostname)
	if config.CloudURL == "" {
		return nil, fmt.Errorf("cloud URL is required")
	}
	if config.Token == "" {
		return nil, fmt.Errorf("bearer token is required")
	}
	if config.DeviceID == "" {
		return nil, fmt.Errorf("device_id is required")
	}
	if strings.TrimSpace(string(csrPEM)) == "" {
		return nil, fmt.Errorf("CSR is required")
	}
	client := config.HTTPClient
	if client == nil {
		var err error
		client, err = buildHTTPClient(config.CAFile)
		if err != nil {
			return nil, err
		}
	}
	requestBody := estEnrollmentRequest{
		DeviceID:             config.DeviceID,
		Component:            endpointComponent,
		Hostname:             config.Hostname,
		CSRPEM:               string(csrPEM),
		PublicKeyFingerprint: strings.TrimSpace(publicKeyFingerprint),
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("marshal EST enrollment request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, config.CloudURL+"/.well-known/est/ztna/simpleenroll", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build EST enrollment request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+config.Token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if config.Nonce != "" {
		request.Header.Set("X-ZTNA-Enrollment-Nonce", config.Nonce)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("POST /.well-known/est/ztna/simpleenroll: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read EST enrollment response: %w", err)
	}
	var enrollmentResponse estEnrollmentResponse
	if len(responseBody) > 0 {
		if err := json.Unmarshal(responseBody, &enrollmentResponse); err != nil {
			return nil, fmt.Errorf("parse EST enrollment response: %w", err)
		}
	}
	if response.StatusCode != http.StatusOK {
		message := strings.TrimSpace(enrollmentResponse.Message)
		if message == "" {
			message = strings.TrimSpace(string(responseBody))
		}
		return nil, fmt.Errorf("EST enrollment failed (HTTP %d): %s", response.StatusCode, message)
	}
	if strings.TrimSpace(enrollmentResponse.CertPEM) == "" {
		return nil, fmt.Errorf("EST enrollment response did not include cert_pem")
	}
	return &ESTResult{
		ID:      strings.TrimSpace(enrollmentResponse.ID),
		CertPEM: []byte(enrollmentResponse.CertPEM),
		CAPEM:   []byte(enrollmentResponse.CAPEM),
	}, nil
}
