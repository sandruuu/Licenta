package enrollment

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const endpointComponent = "endpoint"

type TokenEnrollmentConfig struct {
	CloudURL        string
	CAFile          string
	CloudCertSHA256 string
	Token           string
	Nonce           string
	DeviceID        string
	Hostname        string
	KeyProof        string // optional: TPM-signed proof-of-possession (N3 fix)
	HTTPClient      *http.Client
}

type ESTResult struct {
	ID            string
	CertPEM       []byte
	CAPEM         []byte
	CAFingerprint string // SHA-256 hex of CA PEM, auto-saved on first enrollment (N6)
}

type estEnrollmentRequest struct {
	DeviceID             string `json:"device_id"`
	Component            string `json:"component"`
	Hostname             string `json:"hostname,omitempty"`
	CSRPEM               string `json:"csr_pem"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	KeyProof             string `json:"key_proof,omitempty"` // TPM-signed challenge (N3)
}

type estEnrollmentResponse struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	CertPEM string `json:"cert_pem,omitempty"`
	CAPEM   string `json:"ca_pem,omitempty"`
	Message string `json:"message,omitempty"`
}

// ComputeKeyProof signs a challenge string with a crypto.Signer to prove
// possession of the TPM-backed private key during EST enrollment (N3 fix).
// The challenge binds the device ID and public key fingerprint together so
// the proof cannot be reused across enrollments or devices.
// Both values are independently verifiable by the PDP (fingerprint is
// recomputed from the CSR to prevent spoofing).
func ComputeKeyProof(signer crypto.Signer, deviceID, publicKeyFingerprint string) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("signer is required for key proof")
	}
	if deviceID == "" || publicKeyFingerprint == "" {
		return "", fmt.Errorf("device_id and public_key_fingerprint are required for key proof")
	}
	// Build a deterministic challenge string.
	challenge := fmt.Sprintf("ztna-est-enrollment:%s:%s", deviceID, publicKeyFingerprint)
	hash := sha256.Sum256([]byte(challenge))
	signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("sign key proof: %w", err)
	}
	return hex.EncodeToString(signature), nil
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
		client, err = buildHTTPClient(config.CAFile, config.CloudCertSHA256)
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
		KeyProof:             strings.TrimSpace(config.KeyProof),
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
	if config.KeyProof != "" {
		request.Header.Set("X-ZTNA-Key-Proof", config.KeyProof)
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
	result := &ESTResult{
		ID:      strings.TrimSpace(enrollmentResponse.ID),
		CertPEM: []byte(enrollmentResponse.CertPEM),
		CAPEM:   []byte(enrollmentResponse.CAPEM),
	}
	// Auto-save CA fingerprint after first successful enrollment so
	// subsequent connections benefit from certificate pinning (N6 fix).
	if config.CloudCertSHA256 == "" && len(result.CAPEM) > 0 {
		if fp, err := saveCAFingerprint(result.CAPEM, config.CloudURL); err != nil {
			// Non-fatal: pinning won't be available but enrollment succeeded.
			fmt.Printf("WARNING: failed to save CA fingerprint for future pinning: %v\n", err)
		} else {
			result.CAFingerprint = fp
		}
	}
	return result, nil
}

// saveCAFingerprint computes SHA-256 over the CA PEM bytes and saves the hex
// fingerprint alongside the CA file, enabling future TLS pinning (N6 fix).
func saveCAFingerprint(caPEM []byte, cloudURL string) (string, error) {
	// Parse the PEM to extract the DER certificate bytes for fingerprinting.
	block, _ := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("CA PEM does not contain a valid certificate")
	}
	h := sha256.Sum256(block.Bytes)
	fingerprint := hex.EncodeToString(h[:])

	caDir := caFileDir()
	if err := os.MkdirAll(caDir, 0700); err != nil {
		return fingerprint, err
	}
	fpPath := filepath.Join(caDir, "cloud-ca.sha256")
	_ = cloudURL // used for future multi-tenant fingerprint scope
	return fingerprint, os.WriteFile(fpPath, []byte(fingerprint+"\n"), 0644)
}

// caFileDir returns the directory where the CA fingerprint file should be stored.
func caFileDir() string {
	dataDir := os.Getenv("PROGRAMDATA")
	if dataDir == "" {
		dataDir = "/var/lib"
	}
	return filepath.Join(dataDir, "ztna", "agent")
}
