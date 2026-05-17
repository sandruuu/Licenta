package enrollment

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	gatewaycert "gateway/internal/cert"
	"gateway/internal/config"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/structpb"
)

type Result struct {
	Status         EnrollmentStatus
	GatewayID      string
	OrganizationID string
	FQDN           string
}

type EnrollmentStatus string

const (
	EnrollmentStatusCreated  EnrollmentStatus = "created"
	EnrollmentStatusExisting EnrollmentStatus = "existing"
	EnrollmentStatusRenewed  EnrollmentStatus = "renewed"
)

type enrollRequest struct {
	Token  string
	CSRPEM string
}

type enrollResponse struct {
	Status  string
	CertPEM string
	CAPEM   string
	Message string
}

const (
	gatewayEnrollmentGRPCEnroll    = "/gateway.GatewayEnrollmentService/Enroll"
	gatewayEnrollmentGRPCRenewCert = "/gateway.GatewayEnrollmentService/RenewCertificate"
)

func Ensure(ctx context.Context, cfg *config.Config) (*Result, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if hasFile(config.GatewayCertPath) && hasFile(config.GatewayKeyPath) {
		return loadExistingEnrollment(ctx, cfg)
	}
	return enrollWithToken(ctx, cfg)
}

func loadExistingEnrollment(ctx context.Context, cfg *config.Config) (*Result, error) {
	cert, err := gatewaycert.LoadGatewayKeyPair(config.GatewayCertPath, config.GatewayKeyPath)
	if err != nil {
		return nil, fmt.Errorf("[GATEWAY] load enrolled gateway certificate: %w", err)
	}
	if err := gatewaycert.ValidateGatewayCertificateForRenewal(cert.Leaf); err != nil {
		return nil, fmt.Errorf("[GATEWAY] enrolled gateway certificate is unusable: %w", err)
	}
	if gatewaycert.GatewayCertificateExpired(cert.Leaf) {
		return renewExistingEnrollment(ctx, cfg, cert.Leaf)
	}
	if err := gatewaycert.ValidateGatewayCertificate(cert.Leaf); err != nil {
		return nil, fmt.Errorf("[GATEWAY] enrolled gateway certificate is invalid: %w", err)
	}
	identity, err := gatewaycert.GatewayIdentityFromCertificate(cert.Leaf)
	if err != nil {
		return nil, fmt.Errorf("[GATEWAY] enrolled gateway certificate identity: %w", err)
	}
	applyGatewayIdentity(cfg, identity)
	return resultFromIdentity(EnrollmentStatusExisting, identity), nil
}

func enrollWithToken(ctx context.Context, cfg *config.Config) (*Result, error) {
	if cfg.EnrollmentToken == "" {
		return nil, fmt.Errorf("[GATEWAY] gateway has no enrollment token: enrollment is required")
	}
	if cfg.PAURL == "" {
		return nil, fmt.Errorf("[GATEWAY] PA URL is required for gateway enrollment")
	}

	privateKey, csrPEM, err := createCSR()
	if err != nil {
		return nil, fmt.Errorf("[GATEWAY] create CSR: %w", err)
	}

	if err := writeEnrollmentKeyAndCSR(privateKey, csrPEM); err != nil {
		return nil, fmt.Errorf("[GATEWAY] write enrollment key and CSR: %w", err)
	}

	result, err := enrollGateway(ctx, cfg, enrollRequest{
		Token:  cfg.EnrollmentToken,
		CSRPEM: csrPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("[GATEWAY] enroll gateway: %w", err)
	}
	if result.Status != "enrolled" {
		return nil, fmt.Errorf("[GATEWAY] enrollment did not return a signed certificate: %s", result.Message)
	}
	gatewayCert, err := gatewaycert.ParseGatewayCertificatePEM([]byte(result.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("[GATEWAY] enrollment returned invalid gateway certificate: %w", err)
	}
	if err := gatewaycert.ValidateGatewayCertificate(gatewayCert); err != nil {
		return nil, fmt.Errorf("[GATEWAY] enrollment returned unusable gateway certificate: %w", err)
	}
	identity, err := gatewaycert.GatewayIdentityFromCertificate(gatewayCert)
	if err != nil {
		return nil, fmt.Errorf("[GATEWAY] enrollment returned certificate without gateway identity: %w", err)
	}
	if err := writeEnrollmentCertificate(result); err != nil {
		return nil, err
	}
	applyGatewayIdentity(cfg, identity)
	return resultFromIdentity(EnrollmentStatusCreated, identity), nil
}

func renewExistingEnrollment(ctx context.Context, cfg *config.Config, currentCert *x509.Certificate) (*Result, error) {
	privateKey, csrPEM, err := createRenewalCSR(currentCert)
	if err != nil {
		return nil, fmt.Errorf("[GATEWAY] create renewal CSR: %w", err)
	}
	result, err := renewGatewayGRPC(ctx, cfg, csrPEM)
	if err != nil {
		return nil, fmt.Errorf("[GATEWAY] renew expired gateway certificate: %w", err)
	}
	if result.Status != "renewed" {
		return nil, fmt.Errorf("[GATEWAY] renewal did not return a signed certificate: %s", result.Message)
	}
	renewedCert, err := gatewaycert.ParseGatewayCertificatePEM([]byte(result.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("[GATEWAY] renewal returned invalid gateway certificate: %w", err)
	}
	if err := gatewaycert.ValidateGatewayCertificate(renewedCert); err != nil {
		return nil, fmt.Errorf("[GATEWAY] renewal returned unusable gateway certificate: %w", err)
	}
	renewedIdentity, err := gatewaycert.GatewayIdentityFromCertificate(renewedCert)
	if err != nil {
		return nil, fmt.Errorf("[GATEWAY] renewal returned certificate without gateway identity: %w", err)
	}
	if err := writeRenewedCertificateAndKey(privateKey, result); err != nil {
		return nil, err
	}
	applyGatewayIdentity(cfg, renewedIdentity)
	return resultFromIdentity(EnrollmentStatusRenewed, renewedIdentity), nil
}

func writeEnrollmentKeyAndCSR(privateKey *ecdsa.PrivateKey, csrPEM string) error {
	keyPEM, err := gatewaycert.EncodePrivateKeyPEM(privateKey)
	if err != nil {
		return fmt.Errorf("encode enrollment key: %w", err)
	}
	if err := config.AtomicWriteFile(config.GatewayKeyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write enrollment key: %w", err)
	}
	if err := config.AtomicWriteFile(config.GatewayCSRPath, []byte(csrPEM), 0o600); err != nil {
		return fmt.Errorf("write enrollment CSR: %w", err)
	}
	return nil
}

func writeRenewedCertificateAndKey(privateKey *ecdsa.PrivateKey, result *enrollResponse) error {
	keyPEM, err := gatewaycert.EncodePrivateKeyPEM(privateKey)
	if err != nil {
		return fmt.Errorf("encode renewed key: %w", err)
	}
	if err := config.AtomicWriteFile(config.GatewayKeyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write renewed key: %w", err)
	}
	if err := writeEnrollmentCertificate(result); err != nil {
		return err
	}
	return nil
}

func writeEnrollmentCertificate(result *enrollResponse) error {
	if err := config.AtomicWriteFile(config.GatewayCertPath, []byte(result.CertPEM), 0o644); err != nil {
		return fmt.Errorf("write enrollment certificate: %w", err)
	}
	if result.CAPEM == "" {
		return nil
	}
	if err := config.AtomicWriteFile(config.PACAPath, []byte(result.CAPEM), 0o644); err != nil {
		return fmt.Errorf("write PA CA: %w", err)
	}
	return nil
}

func applyGatewayIdentity(cfg *config.Config, identity gatewaycert.GatewayIdentity) {
	if cfg.ControlPlane == nil {
		cfg.ControlPlane = &config.ControlPlaneConfig{}
	}
	cfg.ControlPlane.GatewayID = identity.GatewayID
	cfg.ControlPlane.OrganizationID = identity.OrganizationID
	cfg.ControlPlane.FQDN = identity.FQDN
}

func resultFromIdentity(status EnrollmentStatus, identity gatewaycert.GatewayIdentity) *Result {
	return &Result{
		Status:         status,
		GatewayID:      identity.GatewayID,
		OrganizationID: identity.OrganizationID,
		FQDN:           identity.FQDN,
	}
}

func createCSR() (*ecdsa.PrivateKey, string, error) {
	key, err := gatewaycert.GenerateGatewayPrivateKey()
	if err != nil {
		return nil, "", fmt.Errorf("generate enrollment key: %w", err)
	}
	ekuExtension, err := gatewaycert.GatewayExtendedKeyUsageExtension()
	if err != nil {
		return nil, "", err
	}
	request := &x509.CertificateRequest{
		ExtraExtensions: []pkix.Extension{
			ekuExtension,
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		return nil, "", fmt.Errorf("create enrollment CSR: %w", err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), nil
}

func createRenewalCSR(currentCert *x509.Certificate) (*ecdsa.PrivateKey, string, error) {
	if currentCert == nil {
		return nil, "", fmt.Errorf("current gateway certificate is required")
	}
	key, err := gatewaycert.GenerateGatewayPrivateKey()
	if err != nil {
		return nil, "", fmt.Errorf("generate renewal key: %w", err)
	}
	ekuExtension, err := gatewaycert.GatewayExtendedKeyUsageExtension()
	if err != nil {
		return nil, "", err
	}
	request := &x509.CertificateRequest{
		DNSNames:    append([]string(nil), currentCert.DNSNames...),
		IPAddresses: append([]net.IP(nil), currentCert.IPAddresses...),
		URIs:        append([]*url.URL(nil), currentCert.URIs...),
		ExtraExtensions: []pkix.Extension{
			ekuExtension,
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		return nil, "", fmt.Errorf("create renewal CSR: %w", err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), nil
}

func enrollGateway(ctx context.Context, cfg *config.Config, request enrollRequest) (*enrollResponse, error) {
	target, serverName, err := config.PATargetFromURL(cfg.PAURL)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := enrollmentTLSConfig()
	if err != nil {
		return nil, err
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = serverName
	}
	conn, err := grpc.DialContext(ctx, target, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("dial gateway enrollment service: %w", err)
	}
	defer conn.Close()

	payload, err := structpb.NewStruct(map[string]interface{}{
		"token":   request.Token,
		"csr_pem": request.CSRPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("build enrollment request: %w", err)
	}
	response := &structpb.Struct{}
	if err := conn.Invoke(ctx, gatewayEnrollmentGRPCEnroll, payload, response); err != nil {
		return nil, fmt.Errorf("send enrollment request: %w", err)
	}
	return enrollResponseFromStruct(response), nil
}

func renewGatewayGRPC(ctx context.Context, cfg *config.Config, csrPEM string) (*enrollResponse, error) {
	target, serverName, err := config.PATargetFromURL(cfg.PAURL)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := enrollmentRenewalTLSConfig()
	if err != nil {
		return nil, err
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = serverName
	}
	conn, err := grpc.DialContext(ctx, target, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("dial gateway renewal service: %w", err)
	}
	defer conn.Close()

	payload, err := structpb.NewStruct(map[string]interface{}{"csr_pem": csrPEM})
	if err != nil {
		return nil, fmt.Errorf("build renewal request: %w", err)
	}
	response := &structpb.Struct{}
	if err := conn.Invoke(ctx, gatewayEnrollmentGRPCRenewCert, payload, response); err != nil {
		return nil, fmt.Errorf("send renewal request: %w", err)
	}
	return enrollResponseFromStruct(response), nil
}

func enrollResponseFromStruct(value *structpb.Struct) *enrollResponse {
	return &enrollResponse{
		Status:  structFieldString(value, "status"),
		CertPEM: structFieldString(value, "cert_pem"),
		CAPEM:   structFieldString(value, "ca_pem"),
		Message: structFieldString(value, "message"),
	}
}

func enrollmentTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	caPath := config.PACAPath
	if hasFile(caPath) {
		data, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("parse PA CA %s", caPath)
		}
		tlsConfig.RootCAs = pool
	}
	return tlsConfig, nil
}

func enrollmentRenewalTLSConfig() (*tls.Config, error) {
	tlsConfig, err := enrollmentTLSConfig()
	if err != nil {
		return nil, err
	}
	cert, err := gatewaycert.LoadGatewayKeyPair(config.GatewayCertPath, config.GatewayKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load gateway mTLS cert for renewal: %w", err)
	}
	if err := gatewaycert.ValidateGatewayCertificateForRenewal(cert.Leaf); err != nil {
		return nil, fmt.Errorf("gateway certificate cannot be used for renewal: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}
	return tlsConfig, nil
}

func structFieldString(value *structpb.Struct, key string) string {
	if value == nil {
		return ""
	}
	field, ok := value.GetFields()[key]
	if !ok || field == nil {
		return ""
	}
	return strings.TrimSpace(field.GetStringValue())
}

func hasFile(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
