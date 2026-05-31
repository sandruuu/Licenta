package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"gateway/internal/cert"
	"gateway/internal/config"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	requestTimeout       = 10 * time.Second
	certRenewalTimeout   = 20 * time.Second
	circuitMaxFailures   = 5
	circuitOpenTimeout   = 30 * time.Second
	circuitProbeMaxDelay = 2 * time.Second
)

// Gateway client for PA communication.
type Client struct {
	target         string
	publicEndpoint string
	tlsConfig      *tls.Config

	renewalTimeout time.Duration

	mu      sync.RWMutex
	breaker *CircuitBreaker
}

func NewClient(cfg *config.Config) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	target, serverName, err := config.PATargetFromURL(cfg.PAURL)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := buildTLSConfig(serverName)
	if err != nil {
		return nil, err
	}
	return &Client{
		target:         target,
		publicEndpoint: strings.TrimSpace(cfg.PublicEndpoint),
		tlsConfig:      tlsConfig,
		renewalTimeout: certRenewalTimeout,
		breaker: NewCircuitBreaker(CircuitBreakerConfig{
			MaxFailures:        circuitMaxFailures,
			OpenTimeout:        circuitOpenTimeout,
			HalfOpenMaxLatency: circuitProbeMaxDelay,
		}),
	}, nil
}

func buildTLSConfig(defaultServerName string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: strings.TrimSpace(defaultServerName),
	}

	caCertPool, err := paRootCAPool()
	if err != nil {
		return nil, err
	}
	tlsConfig.RootCAs = caCertPool

	cert, err := cert.LoadGatewayKeyPairAndValidateCert(config.GatewayCertPath, config.GatewayKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load gateway mTLS cert: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}
	log.Printf("[PA] gRPC client using CA from %s", config.PACAPath)

	return tlsConfig, nil
}

func paRootCAPool() (*x509.CertPool, error) {
	caCert, err := os.ReadFile(config.PACAPath)
	if err != nil {
		return nil, fmt.Errorf("read PA CA: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse PA CA")
	}
	return caCertPool, nil
}

func (client *Client) invokeUnary(ctx context.Context, method string, request *structpb.Struct) (*structpb.Struct, error) {
	var response *structpb.Struct
	_, err := client.breaker.Execute(func() ([]byte, error) {
		result, invokeErr := client.invokeUnaryOnce(ctx, method, request)
		if invokeErr != nil {
			return nil, invokeErr
		}
		response = result
		return []byte("ok"), nil
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (client *Client) invokeUnaryOnce(ctx context.Context, method string, request *structpb.Struct) (*structpb.Struct, error) {
	conn, err := client.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	response := &structpb.Struct{}
	if err := conn.Invoke(ctx, method, request, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (client *Client) dial(ctx context.Context) (*grpc.ClientConn, error) {
	tlsConfig, err := client.grpcTLSConfig()
	if err != nil {
		return nil, err
	}
	conn, err := grpc.DialContext(ctx, client.target, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("dial PA gRPC service: %w", err)
	}
	return conn, nil
}

func (client *Client) grpcTLSConfig() (*tls.Config, error) {
	client.mu.RLock()
	defer client.mu.RUnlock()
	if client.tlsConfig == nil {
		return nil, fmt.Errorf("PA client TLS configuration is not initialized")
	}
	return client.tlsConfig.Clone(), nil
}

func (client *Client) ReloadTLSCert(certPath, keyPath string) error {
	cert, err := cert.LoadGatewayKeyPairAndValidateCert(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("reload mTLS cert: %w", err)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.tlsConfig == nil {
		return fmt.Errorf("PA client TLS configuration is not initialized")
	}
	caCertPool, err := paRootCAPool()
	if err != nil {
		return err
	}
	client.tlsConfig.RootCAs = caCertPool
	client.tlsConfig.Certificates = []tls.Certificate{cert}
	log.Printf("[PA] mTLS certificate reloaded from %s", certPath)
	return nil
}

func (client *Client) Close() {
}
