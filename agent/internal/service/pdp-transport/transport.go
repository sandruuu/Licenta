package pdptransport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const DefaultMinTLSVersion = tls.VersionTLS13

type Config struct {
	Endpoint     string
	ServerName   string
	CAFile       string
	Certificates []tls.Certificate
	MinVersion   uint16
}

func NewTLSConfig(config Config) (*tls.Config, error) {
	minVersion := config.MinVersion
	if minVersion == 0 || minVersion < DefaultMinTLSVersion {
		minVersion = DefaultMinTLSVersion
	}
	tlsConfig := &tls.Config{
		MinVersion:   minVersion,
		ServerName:   strings.TrimSpace(config.ServerName),
		Certificates: config.Certificates,
	}
	caFile := strings.TrimSpace(config.CAFile)
	if caFile == "" {
		return tlsConfig, nil
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read pdp_ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("pdp_ca_file contains no certificates")
	}
	tlsConfig.RootCAs = pool
	return tlsConfig, nil
}

func NewClient(config Config, purpose string) (*grpc.ClientConn, error) {
	target, err := Endpoint(config.Endpoint, purpose)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := NewTLSConfig(config)
	if err != nil {
		return nil, err
	}
	connection, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		if trimmed := clientPurpose(purpose); trimmed != "" {
			return nil, fmt.Errorf("create PDP %s gRPC client: %w", trimmed, err)
		}
		return nil, fmt.Errorf("create PDP gRPC client: %w", err)
	}
	return connection, nil
}

func Endpoint(value, purpose string) (string, error) {
	endpoint := strings.TrimSpace(value)
	if endpoint != "" {
		return endpoint, nil
	}
	purpose = strings.TrimSpace(purpose)
	if purpose == "" {
		return "", fmt.Errorf("pdp_grpc_endpoint is required")
	}
	return "", fmt.Errorf("pdp_grpc_endpoint is required for %s", purpose)
}

func clientPurpose(purpose string) string {
	purpose = strings.TrimSpace(purpose)
	if purpose == "" {
		return ""
	}
	return purpose
}
