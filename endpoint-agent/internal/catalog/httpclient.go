package catalog

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// HTTPClientConfig configures the mTLS HTTP catalog client.
type HTTPClientConfig struct {
	// CloudURL is the base URL of the Cloud API (e.g. "https://cloud:8443").
	CloudURL string

	// CertPEM is the device certificate PEM used for mTLS.
	CertPEM []byte
	CAPEM   []byte
	Signer  crypto.Signer

	// CAFile is the path to the Cloud CA certificate file.
	CAFile string

	// Timeout for each sync request.
	Timeout time.Duration
}

type catalogRequest struct {
	CurrentVersion string `json:"current_version,omitempty"`
}

type catalogResponse struct {
	Version    string         `json:"version"`
	Entries    []CatalogEntry `json:"entries"`
	UpdatedAt  time.Time      `json:"updated_at"`
	TTLSeconds int            `json:"ttl_seconds,omitempty"`
}

// HTTPClient implements SyncClient over HTTP/2 + mTLS.
type HTTPClient struct {
	cloudURL   string
	httpClient *http.Client
}

// NewHTTPClient creates a catalog sync client using device mTLS credentials.
func NewHTTPClient(config HTTPClientConfig) (*HTTPClient, error) {
	cloudURL := strings.TrimRight(strings.TrimSpace(config.CloudURL), "/")
	if cloudURL == "" {
		return nil, fmt.Errorf("catalog sync requires cloud_url")
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}

	// Load CA pool.
	caPool, err := buildCAPool(config.CAPEM, config.CAFile)
	if err != nil {
		return nil, err
	}
	if caPool != nil {
		tlsConfig.RootCAs = caPool
	}

	if len(config.CertPEM) == 0 || config.Signer == nil {
		return nil, fmt.Errorf("catalog sync requires device mTLS certificate and signer")
	}
	cert, err := buildTLSCertificate(config.CertPEM, config.Signer)
	if err != nil {
		return nil, fmt.Errorf("build mTLS certificate: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	return &HTTPClient{
		cloudURL: cloudURL,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig:   tlsConfig,
				ForceAttemptHTTP2: true,
			},
		},
	}, nil
}

// FetchCatalog retrieves the latest catalog from Cloud.
// Returns nil, nil when the catalog has not changed (HTTP 304).
func (c *HTTPClient) FetchCatalog(ctx context.Context, currentVersion string) (*Catalog, error) {
	endpoint := c.cloudURL + "/api/device/catalog"

	reqBody := catalogRequest{CurrentVersion: strings.TrimSpace(currentVersion)}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal catalog request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return nil, fmt.Errorf("build catalog request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST /api/device/catalog: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read catalog response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalog sync failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var catalogResp catalogResponse
	if err := json.Unmarshal(body, &catalogResp); err != nil {
		return nil, fmt.Errorf("parse catalog response: %w", err)
	}

	updatedAt := catalogResp.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}

	return &Catalog{
		Version:   catalogResp.Version,
		Entries:   catalogResp.Entries,
		UpdatedAt: updatedAt,
	}, nil
}

func buildCAPool(caPEM []byte, caFile string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	added := false

	if len(caPEM) > 0 {
		if pool.AppendCertsFromPEM(caPEM) {
			added = true
		}
	}

	caFile = strings.TrimSpace(caFile)
	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file %s: %w", caFile, err)
		}
		if pool.AppendCertsFromPEM(data) {
			added = true
		}
	}

	if !added {
		return nil, nil
	}
	return pool, nil
}

func buildTLSCertificate(certPEM []byte, signer crypto.Signer) (tls.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return tls.Certificate{}, fmt.Errorf("device certificate is not PEM encoded")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse device certificate: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{leaf.Raw},
		PrivateKey:  signer,
		Leaf:        leaf,
	}, nil
}
