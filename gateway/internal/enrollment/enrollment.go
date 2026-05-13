package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"gateway/internal/config"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/structpb"
)

type Result struct {
	Enrolled  bool
	GatewayID string
	TenantID  string
}

type enrollRequest struct {
	Token     string `json:"token"`
	CSRPEM    string `json:"csr_pem"`
	FQDN      string `json:"fqdn"`
	Name      string `json:"name,omitempty"`
	GatewayID string `json:"gateway_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}

type enrollResponse struct {
	Status    string `json:"status"`
	GatewayID string `json:"gateway_id"`
	TenantID  string `json:"tenant_id,omitempty"`
	CertPEM   string `json:"cert_pem"`
	CAPEM     string `json:"ca_pem"`
	Message   string `json:"message,omitempty"`
}

const (
	enrollmentTimeout            = 30 * time.Second
	gatewayEnrollmentGRPCEnroll  = "/ztna.gateway.v1.GatewayEnrollmentService/Enroll"
	gatewayEnrollmentIdentityURI = "spiffe://ztna.local/tenant/%s/gateway/%s"
)

func Ensure(ctx context.Context, cfg *config.Config) (*Result, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if hasFile(cfg.MTLSCert) && hasFile(cfg.MTLSKey) {
		return &Result{}, nil
	}
	enrollCtx, cancel := context.WithTimeout(ctx, enrollmentTimeout)
	defer cancel()
	if strings.TrimSpace(cfg.EnrollmentToken) == "" {
		return nil, fmt.Errorf("gateway has no mTLS certificate and no enrollment token: enrollment is required")
	}
	if strings.TrimSpace(cfg.CloudURL) == "" {
		return nil, fmt.Errorf("cloud_url is required for gateway enrollment")
	}
	if cfg.ControlPlane == nil {
		cfg.ControlPlane = &config.ControlPlaneConfig{}
	}
	gatewayID := strings.TrimSpace(cfg.ControlPlane.GatewayID)
	tenantID := strings.TrimSpace(cfg.TenantID)
	if gatewayID == "" {
		return nil, fmt.Errorf("control_plane.gateway_id is required for gateway enrollment")
	}
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required for gateway enrollment")
	}

	applyDefaultPaths(cfg)
	privateKey, csrPEM, err := createCSR(gatewayID, tenantID, cfg.FQDN)
	if err != nil {
		return nil, err
	}

	keyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := config.AtomicWriteFile(cfg.MTLSKey, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, fmt.Errorf("write enrollment key: %w", err)
	}
	if cfg.MTLSCSR != "" {
		if err := config.AtomicWriteFile(cfg.MTLSCSR, []byte(csrPEM), 0o600); err != nil {
			return nil, fmt.Errorf("write enrollment CSR: %w", err)
		}
	}

	result, err := enrollGatewayGRPC(enrollCtx, cfg, enrollRequest{
		Token:     cfg.EnrollmentToken,
		CSRPEM:    csrPEM,
		FQDN:      cfg.FQDN,
		Name:      firstNonEmpty(cfg.FQDN, "ZTNA Gateway"),
		GatewayID: gatewayID,
		TenantID:  tenantID,
	})
	if err != nil {
		return nil, err
	}
	if result.Status != "enrolled" || strings.TrimSpace(result.CertPEM) == "" {
		return nil, fmt.Errorf("enrollment did not return a signed certificate: %s", result.Message)
	}
	if result.GatewayID != "" && result.GatewayID != gatewayID {
		return nil, fmt.Errorf("enrollment response gateway_id %q does not match configured gateway_id %q", result.GatewayID, gatewayID)
	}
	if result.TenantID != "" && result.TenantID != tenantID {
		return nil, fmt.Errorf("enrollment response tenant_id %q does not match configured tenant_id %q", result.TenantID, tenantID)
	}
	if err := config.AtomicWriteFile(cfg.MTLSCert, []byte(result.CertPEM), 0o644); err != nil {
		return nil, fmt.Errorf("write enrollment certificate: %w", err)
	}
	if result.CAPEM != "" && cfg.CloudCA != "" {
		if err := config.AtomicWriteFile(cfg.CloudCA, []byte(result.CAPEM), 0o644); err != nil {
			return nil, fmt.Errorf("write cloud CA: %w", err)
		}
		// Auto-save CA fingerprint after first enrollment for future pinning (N6 fix).
		if strings.TrimSpace(cfg.CloudCertSHA256) == "" {
			saveCAFingerprintFile(cfg.CloudCA, []byte(result.CAPEM))
		}
	}

	cfg.ControlPlane.GatewayID = firstNonEmpty(cfg.ControlPlane.GatewayID, result.GatewayID)
	cfg.ControlPlane.CertFile = firstNonEmpty(cfg.ControlPlane.CertFile, cfg.MTLSCert)
	cfg.ControlPlane.KeyFile = firstNonEmpty(cfg.ControlPlane.KeyFile, cfg.MTLSKey)
	cfg.ControlPlane.CAFile = firstNonEmpty(cfg.ControlPlane.CAFile, cfg.CloudCA, cfg.TLSCA)
	cfg.TenantID = firstNonEmpty(cfg.TenantID, result.TenantID)
	cfg.EnrollmentToken = ""
	return &Result{Enrolled: true, GatewayID: result.GatewayID, TenantID: result.TenantID}, nil
}

func applyDefaultPaths(cfg *config.Config) {
	if cfg.MTLSCert == "" {
		cfg.MTLSCert = "certs/gateway-mtls.crt"
	}
	if cfg.MTLSKey == "" {
		cfg.MTLSKey = "certs/gateway-mtls.key"
	}
	if cfg.MTLSCSR == "" {
		cfg.MTLSCSR = "certs/gateway-mtls.csr"
	}
	if cfg.CloudCA == "" {
		cfg.CloudCA = "certs/cloud-ca.crt"
	}
}

func createCSR(gatewayID, tenantID, fqdn string) (*rsa.PrivateKey, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", fmt.Errorf("generate enrollment key: %w", err)
	}
	identityURL, err := url.Parse(fmt.Sprintf(
		gatewayEnrollmentIdentityURI,
		url.PathEscape(strings.TrimSpace(tenantID)),
		url.PathEscape(strings.TrimSpace(gatewayID)),
	))
	if err != nil {
		return nil, "", fmt.Errorf("build gateway identity URI: %w", err)
	}
	request := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: strings.TrimSpace(gatewayID)},
		URIs:    []*url.URL{identityURL},
	}
	if fqdn = strings.TrimSpace(fqdn); fqdn != "" {
		request.DNSNames = []string{fqdn}
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		return nil, "", fmt.Errorf("create enrollment CSR: %w", err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), nil
}

func enrollGatewayGRPC(ctx context.Context, cfg *config.Config, request enrollRequest) (*enrollResponse, error) {
	target, serverName, err := grpcTargetFromCloudURL(cfg.CloudURL)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := enrollmentTLSConfig(cfg)
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
		"token":      request.Token,
		"csr_pem":    request.CSRPEM,
		"fqdn":       request.FQDN,
		"name":       request.Name,
		"gateway_id": request.GatewayID,
		"tenant_id":  request.TenantID,
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

func enrollResponseFromStruct(value *structpb.Struct) *enrollResponse {
	return &enrollResponse{
		Status:    structFieldString(value, "status"),
		GatewayID: structFieldString(value, "gateway_id"),
		TenantID:  structFieldString(value, "tenant_id"),
		CertPEM:   structFieldString(value, "cert_pem"),
		CAPEM:     structFieldString(value, "ca_pem"),
		Message:   structFieldString(value, "message"),
	}
}

func enrollmentTLSConfig(cfg *config.Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	caPath := firstNonEmpty(cfg.CloudCA, cfg.TLSCA)
	if caPath != "" && hasFile(caPath) {
		data, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("parse cloud CA %s", caPath)
		}
		tlsConfig.RootCAs = pool
	}
	pinnedSHA256 := strings.TrimSpace(cfg.CloudCertSHA256)
	if pinnedSHA256 != "" {
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no server certificate presented")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse server certificate: %w", err)
			}
			actual := sha256HexBytes(cert.Raw)
			if !strings.EqualFold(actual, pinnedSHA256) {
				return fmt.Errorf("server certificate SHA-256 %q does not match pinned %q", actual, pinnedSHA256)
			}
			return nil
		}
	}
	return tlsConfig, nil
}

func grpcTargetFromCloudURL(rawURL string) (string, string, error) {
	parsedURL, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", "", fmt.Errorf("parse cloud_url: %w", err)
	}
	if !strings.EqualFold(parsedURL.Scheme, "https") {
		return "", "", fmt.Errorf("cloud_url must use https for gateway enrollment gRPC")
	}
	host := strings.TrimSpace(parsedURL.Host)
	serverName := strings.TrimSpace(parsedURL.Hostname())
	if host == "" || serverName == "" {
		return "", "", fmt.Errorf("cloud_url must include a host")
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(serverName, "443")
	}
	return host, serverName, nil
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

func sha256HexBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hasFile(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// saveCAFingerprintFile writes a SHA-256 fingerprint of the CA certificate
// alongside the CA file so that future enrollments and connections can use
// certificate pinning against a known-good CA (N6 fix).
func saveCAFingerprintFile(caFilePath string, caPEM []byte) {
	block, _ := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return
	}
	h := sha256.Sum256(block.Bytes)
	fingerprint := hex.EncodeToString(h[:])
	fpPath := caFilePath + ".sha256"
	if err := os.WriteFile(fpPath, []byte(fingerprint+"\n"), 0644); err != nil {
		log.Printf("WARNING: failed to save CA fingerprint for pinning: %v", err)
	}
}
