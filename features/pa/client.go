package pa

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	deviceCatalogGetCatalogPath             = "/ztna.catalog.DeviceCatalogService/GetCatalog"
	deviceTelemetryReportPosturePath        = "/trustagent.device.DeviceDataService/ReportDeviceData"
	deviceTelemetryHeartbeatPath            = "/trustagent.device.DeviceDataService/Heartbeat"
	agentAuthorizationAuthorizeResourcePath = "/ztna.agent.AgentAuthorizationService/AuthorizeResource"
)

type CertificateProvider func(context.Context) (tls.Certificate, error)

type AccessTokenProvider func() (accessToken, deviceID string)

type Config struct {
	PAURL               string
	CAFile              string
	ServerCertSHA256    string
	CertificateProvider CertificateProvider
	AccessTokenProvider AccessTokenProvider
	Timeout             time.Duration
	DialOptions         []grpc.DialOption
}

type Client struct {
	paURL               string
	caFile              string
	serverCertSHA256    string
	certificateProvider CertificateProvider
	accessTokenProvider AccessTokenProvider
	timeout             time.Duration
	dialOptions         []grpc.DialOption
}

func NewClient(config Config) (*Client, error) {
	paURL := strings.TrimRight(strings.TrimSpace(config.PAURL), "/")
	if paURL == "" {
		return nil, errors.New("PA URL is required")
	}
	timeout := config.Timeout
	if timeout <= 0 {
		return nil, errors.New("PA request timeout is required")
	}
	return &Client{
		paURL:               paURL,
		caFile:              strings.TrimSpace(config.CAFile),
		serverCertSHA256:    strings.TrimSpace(config.ServerCertSHA256),
		certificateProvider: config.CertificateProvider,
		accessTokenProvider: config.AccessTokenProvider,
		timeout:             timeout,
		dialOptions:         append([]grpc.DialOption(nil), config.DialOptions...),
	}, nil
}
func (client *Client) Close() error {
	return nil
}

type invokeOptions struct {
	AccessToken           string
	UseMachineCertificate bool
	Certificate           *tls.Certificate
}

func (client *Client) invoke(ctx context.Context, method string, request *structpb.Struct, response *structpb.Struct, options invokeOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, client.timeout)
		defer cancel()
	}
	if strings.TrimSpace(options.AccessToken) != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+strings.TrimSpace(options.AccessToken))
	}
	certificate, err := client.certificate(ctx, options)
	if err != nil {
		return err
	}
	tlsConfig, err := client.tlsConfig(certificate)
	if err != nil {
		return err
	}
	target, err := grpcTargetFromPAURL(client.paURL)
	if err != nil {
		return err
	}
	dialOptions := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}
	dialOptions = append(dialOptions, client.dialOptions...)
	conn, err := grpc.DialContext(ctx, target, dialOptions...)
	if err != nil {
		return fmt.Errorf("dial PA gRPC endpoint: %w", err)
	}
	defer conn.Close()
	if err := conn.Invoke(ctx, method, request, response); err != nil {
		return fmt.Errorf("invoke PA gRPC method %s: %w", method, err)
	}
	return nil
}

func (client *Client) certificate(ctx context.Context, options invokeOptions) (*tls.Certificate, error) {
	if options.Certificate != nil {
		if len(options.Certificate.Certificate) == 0 || options.Certificate.PrivateKey == nil {
			return nil, errors.New("client certificate is incomplete")
		}
		return options.Certificate, nil
	}
	if !options.UseMachineCertificate {
		return nil, nil
	}
	if client.certificateProvider == nil {
		return nil, errors.New("machine certificate provider is required")
	}
	certificate, err := client.certificateProvider(ctx)
	if err != nil {
		return nil, fmt.Errorf("load PA gRPC mTLS credential: %w", err)
	}
	return &certificate, nil
}

func (client *Client) tlsConfig(certificate *tls.Certificate) (*tls.Config, error) {
	_, serverName, err := grpcTargetAndServerNameFromPAURL(client.paURL)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName}
	if certificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*certificate}
	}
	if client.caFile != "" {
		pool, err := rootCAPool(client.caFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}
	if client.serverCertSHA256 != "" {
		pinned := client.serverCertSHA256
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("PA gRPC server did not present a certificate")
			}
			actual := sha256Hex(rawCerts[0])
			if !strings.EqualFold(actual, pinned) {
				return fmt.Errorf("PA gRPC server certificate SHA-256 %q does not match pinned %q", actual, pinned)
			}
			return nil
		}
	}
	return tlsConfig, nil
}

func (client *Client) accessToken() (string, string) {
	if client.accessTokenProvider == nil {
		return "", ""
	}
	accessToken, deviceID := client.accessTokenProvider()
	return strings.TrimSpace(accessToken), strings.TrimSpace(deviceID)
}
func rootCAPool(caFile string) (*x509.CertPool, error) {
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

func grpcTargetFromPAURL(raw string) (string, error) {
	target, _, err := grpcTargetAndServerNameFromPAURL(raw)
	return target, err
}

func grpcTargetAndServerNameFromPAURL(raw string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", fmt.Errorf("parse PA URL: %w", err)
	}
	host := parsed.Host
	if host == "" && parsed.Scheme == "" && parsed.Path != "" {
		host = parsed.Path
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", "", errors.New("PA URL host is required")
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}
	serverName := parsed.Hostname()
	if serverName == "" {
		if splitHost, _, err := net.SplitHostPort(host); err == nil {
			serverName = splitHost
		}
	}
	return host, serverName, nil
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
