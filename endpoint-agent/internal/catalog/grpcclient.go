package catalog

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/structpb"
)

const deviceCatalogGRPCGetCatalogPath = "/ztna.catalog.v1.DeviceCatalogService/GetCatalog"

// GRPCClientConfig configures the mTLS gRPC catalog client.
type GRPCClientConfig struct {
	// CloudURL is the base URL of the Cloud API (e.g. "https://cloud:8443").
	CloudURL string

	// CertPEM is the device certificate PEM used for mTLS.
	CertPEM []byte
	CAPEM   []byte
	Signer  crypto.Signer

	// CAFile is the path to the Cloud CA certificate file.
	CAFile string

	// Timeout for dial and request operations.
	Timeout time.Duration
}

// GRPCClient implements SyncClient over gRPC + mTLS.
type GRPCClient struct {
	conn    *grpc.ClientConn
	timeout time.Duration
}

// NewGRPCClient creates a catalog sync client using device mTLS credentials.
func NewGRPCClient(config GRPCClientConfig) (*GRPCClient, error) {
	cloudURL := strings.TrimSpace(config.CloudURL)
	if cloudURL == "" {
		return nil, fmt.Errorf("catalog sync requires cloud_url")
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}

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

	target, serverName, err := grpcTargetFromCloudURL(cloudURL)
	if err != nil {
		return nil, err
	}
	if serverName != "" {
		tlsConfig.ServerName = serverName
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := grpc.DialContext(
		dialCtx,
		target,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("dial catalog gRPC endpoint: %w", err)
	}

	return &GRPCClient{conn: conn, timeout: timeout}, nil
}

// Close terminates the underlying gRPC connection.
func (c *GRPCClient) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// FetchCatalog retrieves the latest catalog from Cloud.
// Returns nil, nil when the catalog has not changed.
func (c *GRPCClient) FetchCatalog(ctx context.Context, currentVersion string) (*Catalog, error) {
	if c == nil || c.conn == nil {
		return nil, fmt.Errorf("catalog gRPC client is not initialized")
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	requestPayload := map[string]interface{}{}
	if version := strings.TrimSpace(currentVersion); version != "" {
		requestPayload["current_version"] = version
	}
	request, err := structpb.NewStruct(requestPayload)
	if err != nil {
		return nil, fmt.Errorf("build catalog gRPC request: %w", err)
	}

	response := &structpb.Struct{}
	if err := c.conn.Invoke(ctx, deviceCatalogGRPCGetCatalogPath, request, response); err != nil {
		return nil, fmt.Errorf("invoke catalog gRPC method: %w", err)
	}

	fields := response.GetFields()
	if fields["not_modified"] != nil && fields["not_modified"].GetBoolValue() {
		return nil, nil
	}

	version := ""
	if fields["version"] != nil {
		version = strings.TrimSpace(fields["version"].GetStringValue())
	}
	if version == "" {
		return nil, fmt.Errorf("catalog gRPC response did not include a version")
	}

	entries := make([]CatalogEntry, 0)
	if fields["entries"] != nil && fields["entries"].GetListValue() != nil {
		for _, value := range fields["entries"].GetListValue().GetValues() {
			entryStruct := value.GetStructValue()
			if entryStruct == nil {
				continue
			}
			entryFields := entryStruct.GetFields()
			entry := CatalogEntry{}
			if entryFields["fqdn"] != nil {
				entry.FQDN = strings.TrimSpace(entryFields["fqdn"].GetStringValue())
			}
			if entryFields["protocol"] != nil {
				entry.Protocol = strings.TrimSpace(entryFields["protocol"].GetStringValue())
			}
			if entryFields["resource_id"] != nil {
				entry.ResourceID = strings.TrimSpace(entryFields["resource_id"].GetStringValue())
			}
			if entryFields["port"] != nil {
				entry.Port = int(entryFields["port"].GetNumberValue())
			}
			if entry.FQDN == "" {
				continue
			}
			entries = append(entries, entry)
		}
	}

	updatedAt := time.Now().UTC()
	if fields["updated_at"] != nil {
		if parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(fields["updated_at"].GetStringValue())); err == nil {
			updatedAt = parsed.UTC()
		}
	}

	return &Catalog{
		Version:   version,
		Entries:   entries,
		UpdatedAt: updatedAt,
	}, nil
}

func grpcTargetFromCloudURL(raw string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", fmt.Errorf("parse cloud_url: %w", err)
	}

	host := parsed.Host
	if host == "" && parsed.Scheme == "" && parsed.Path != "" {
		host = parsed.Path
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", "", fmt.Errorf("catalog sync requires cloud_url host")
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}

	serverName := ""
	if parsed.Hostname() != "" {
		serverName = parsed.Hostname()
	}
	if serverName == "" {
		if splitHost, _, err := net.SplitHostPort(host); err == nil {
			serverName = splitHost
		}
	}

	return host, serverName, nil
}
