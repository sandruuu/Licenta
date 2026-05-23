package pdpclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"

	"agent/internal/service/enrollment"
	pdptransport "agent/internal/service/pdp-transport"

	"google.golang.org/grpc"
)

type Config struct {
	PDPGRPCEndpoint  string
	PDPTLSServerName string
	PDPCAFile        string
}

type Client struct {
	mu       sync.Mutex
	config   Config
	identity enrollment.DeviceIdentity

	connection     *grpc.ClientConn
	cleanup        func()
	deviceID       string
	certThumbprint string
}

func New(config Config, identity enrollment.DeviceIdentity) *Client {
	config.PDPGRPCEndpoint = strings.TrimSpace(config.PDPGRPCEndpoint)
	config.PDPTLSServerName = strings.TrimSpace(config.PDPTLSServerName)
	config.PDPCAFile = strings.TrimSpace(config.PDPCAFile)
	if identity == nil {
		identity = enrollment.NewDefaultDeviceIdentity()
	}
	return &Client{config: config, identity: identity}
}

func (client *Client) Connection(ctx context.Context, record enrollment.EnrollmentRecord) (*grpc.ClientConn, error) {
	if client == nil {
		return nil, fmt.Errorf("PDP client is not configured")
	}
	client.mu.Lock()
	defer client.mu.Unlock()

	deviceID := strings.TrimSpace(record.DeviceID)
	thumbprint := strings.TrimSpace(record.DeviceCertThumbprint)
	if client.connection != nil && client.deviceID == deviceID && client.certThumbprint == thumbprint {
		return client.connection, nil
	}
	client.closeLocked()

	endpoint, err := pdptransport.Endpoint(client.config.PDPGRPCEndpoint, "")
	if err != nil {
		return nil, err
	}
	certificate, cleanup, err := client.identity.ClientCertificate(ctx, record)
	if err != nil {
		return nil, fmt.Errorf("load device client certificate: %w", err)
	}
	connection, err := pdptransport.NewClient(pdptransport.Config{
		Endpoint:     endpoint,
		ServerName:   client.config.PDPTLSServerName,
		CAFile:       client.config.PDPCAFile,
		Certificates: []tls.Certificate{certificate},
	}, "")
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, err
	}
	client.connection = connection
	client.cleanup = cleanup
	client.deviceID = deviceID
	client.certThumbprint = thumbprint
	return connection, nil
}

func (client *Client) Close() error {
	if client == nil {
		return nil
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.closeLocked()
}

func (client *Client) closeLocked() error {
	if client.cleanup != nil {
		client.cleanup()
		client.cleanup = nil
	}
	var err error
	if client.connection != nil {
		err = client.connection.Close()
		client.connection = nil
	}
	client.deviceID = ""
	client.certThumbprint = ""
	return err
}
