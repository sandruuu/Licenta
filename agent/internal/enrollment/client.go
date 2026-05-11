package enrollment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Client struct {
	cloudURL   string
	httpClient *http.Client
}

type Config struct {
	CloudURL        string
	CAFile          string
	CloudCertSHA256 string
	HTTPClient      *http.Client
}

type TokenRequest struct {
	AccessToken string
	DeviceID    string
	Nonce       string
	UserSID     string
}

type Token struct {
	EnrollmentToken string
	TokenType       string
	ExpiresIn       int
	ExpiresAt       time.Time
	DeviceID        string
	Nonce           string
	UserSID         string
	UserEmail       string
}

func NewClient(config Config) (*Client, error) {
	cloudURL := strings.TrimRight(strings.TrimSpace(config.CloudURL), "/")
	if cloudURL == "" {
		return nil, errors.New("cloud URL is required")
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		client, err := buildHTTPClient(config.CAFile, config.CloudCertSHA256)
		if err != nil {
			return nil, err
		}
		httpClient = client
	}
	return &Client{cloudURL: cloudURL, httpClient: httpClient}, nil
}

func (client *Client) RequestEnrollmentToken(ctx context.Context, request TokenRequest) (*Token, error) {
	if client == nil {
		return nil, errors.New("enrollment client is nil")
	}
	accessToken := strings.TrimSpace(request.AccessToken)
	if accessToken == "" {
		return nil, errors.New("access token is required")
	}
	deviceID := strings.TrimSpace(request.DeviceID)
	if deviceID == "" {
		return nil, errors.New("device_id is required")
	}
	nonce := strings.TrimSpace(request.Nonce)
	if nonce == "" {
		return nil, errors.New("nonce is required")
	}
	body, err := json.Marshal(map[string]string{
		"device_id": deviceID,
		"nonce":     nonce,
		"user_sid":  strings.TrimSpace(request.UserSID),
	})
	if err != nil {
		return nil, fmt.Errorf("encode enrollment token request: %w", err)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.cloudURL+"/api/enroll/token", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build enrollment token request: %w", err)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+accessToken)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpResponse, err := client.httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("request enrollment token: %w", err)
	}
	defer httpResponse.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(httpResponse.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read enrollment token response: %w", err)
	}
	if httpResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enrollment token endpoint returned %d: %s", httpResponse.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	var response tokenResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("decode enrollment token response: %w", err)
	}
	token := &Token{
		EnrollmentToken: strings.TrimSpace(response.EnrollmentToken),
		TokenType:       strings.TrimSpace(response.TokenType),
		ExpiresIn:       response.ExpiresIn,
		DeviceID:        strings.TrimSpace(response.DeviceID),
		Nonce:           strings.TrimSpace(response.Nonce),
		UserSID:         strings.TrimSpace(response.UserSID),
		UserEmail:       strings.TrimSpace(response.UserEmail),
	}
	if token.TokenType == "" {
		token.TokenType = "Bearer"
	}
	if token.EnrollmentToken == "" {
		return nil, errors.New("enrollment_token is required")
	}
	if !strings.EqualFold(token.TokenType, "Bearer") {
		return nil, fmt.Errorf("unsupported token_type %q", token.TokenType)
	}
	if token.ExpiresIn <= 0 {
		return nil, errors.New("expires_in must be positive")
	}
	if token.DeviceID != deviceID {
		return nil, errors.New("device_id in enrollment response does not match request")
	}
	if token.Nonce != nonce {
		return nil, errors.New("nonce in enrollment response does not match request")
	}
	if token.UserSID != "" && token.UserSID != strings.TrimSpace(request.UserSID) {
		return nil, errors.New("user_sid in enrollment response does not match request")
	}
	token.ExpiresAt = time.Now().UTC().Add(time.Duration(token.ExpiresIn) * time.Second)
	return token, nil
}

type tokenResponse struct {
	EnrollmentToken string `json:"enrollment_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	DeviceID        string `json:"device_id"`
	Nonce           string `json:"nonce"`
	UserSID         string `json:"user_sid"`
	UserEmail       string `json:"user_email"`
}

func buildHTTPClient(caFile, cloudCertSHA256 string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	if strings.TrimSpace(caFile) != "" {
		pool, err := enrollmentRootCAPool(caFile)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	setCertPinning(transport.TLSClientConfig, cloudCertSHA256)
	return &http.Client{Timeout: 30 * time.Second, Transport: transport}, nil
}

func buildHTTPClientWithCertificate(caFile, cloudCertSHA256 string, certificate tls.Certificate) (*http.Client, error) {
	if len(certificate.Certificate) == 0 {
		return nil, errors.New("client certificate leaf is required")
	}
	if certificate.PrivateKey == nil {
		return nil, errors.New("client certificate private key is required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	if strings.TrimSpace(caFile) != "" {
		pool, err := enrollmentRootCAPool(caFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}
	setCertPinning(tlsConfig, cloudCertSHA256)
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Timeout: 30 * time.Second, Transport: transport}, nil
}

func setCertPinning(tlsConfig *tls.Config, cloudCertSHA256 string) {
	pinned := strings.TrimSpace(cloudCertSHA256)
	if pinned == "" {
		return
	}
	tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no server certificate presented")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse server certificate: %w", err)
		}
		actual := sha256HexBytes(cert.Raw)
		if !strings.EqualFold(actual, pinned) {
			return fmt.Errorf("server certificate SHA-256 %q does not match pinned %q", actual, pinned)
		}
		return nil
	}
}

func sha256HexBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func enrollmentRootCAPool(caFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("CA file does not contain PEM certificates")
	}
	return pool, nil
}
