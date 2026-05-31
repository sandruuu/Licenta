package gateway

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"pdp/models"
)

func (s *Service) gatewayByID(id string) (*models.Gateway, error) {
	if err := s.readyStore(); err != nil {
		return nil, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("%w: gateway ID required", ErrInvalidRequest)
	}
	gateway, found := s.store.GetGateway(id)
	if !found {
		return nil, ErrGatewayNotFound
	}
	return gateway, nil
}

func (s *Service) ready() error {
	if err := s.readyStore(); err != nil {
		return err
	}
	if s.signer == nil {
		return fmt.Errorf("%w: PKI signer not initialized", ErrGatewaySigning)
	}
	return nil
}

func (s *Service) readyStore() error {
	if s == nil || s.store == nil {
		return ErrGatewayStoreUnavailable
	}
	return nil
}

func (s *Service) validateTenant(tenantID string) (string, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return "", fmt.Errorf("%w: organization_id is required", ErrInvalidRequest)
	}
	tenant, found := s.store.GetTenant(tenantID)
	if !found || tenant == nil || !tenant.Enabled {
		return "", fmt.Errorf("%w: organization not found or disabled", ErrInvalidRequest)
	}
	return tenantID, nil
}

func (s *Service) validateAssignedResourcesTenant(tenantID string, resourceIDs []string) error {
	tenantID = strings.TrimSpace(tenantID)
	for _, resourceID := range resourceIDs {
		resourceID = strings.TrimSpace(resourceID)
		if resourceID == "" {
			continue
		}
		resource, found := s.store.GetResource(resourceID)
		if !found || resource == nil {
			return fmt.Errorf("%w: assigned resource %s not found", ErrInvalidRequest, resourceID)
		}
		if strings.TrimSpace(resource.TenantID) != "" && !strings.EqualFold(resource.TenantID, tenantID) {
			return fmt.Errorf("%w: assigned resource %s belongs to a different organization", ErrInvalidRequest, resourceID)
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (s *Service) clock() time.Time {
	if s != nil && s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Service) certificateValidity() time.Duration {
	if s != nil && s.certificateValidityDays > 0 {
		return time.Duration(s.certificateValidityDays) * 24 * time.Hour
	}
	return time.Duration(defaultCertificateValidityDays) * 24 * time.Hour
}

func tokenExpired(value string, now time.Time) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return false
	}
	return now.After(expiresAt)
}

func parseGatewayCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("%w: invalid CSR PEM", ErrInvalidCSR)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: CSR signature invalid: %v", ErrInvalidCSR, err)
	}
	return csr, nil
}

func gatewayCertificateProfile(gateway *models.Gateway) (CertificateProfile, error) {
	if gateway == nil {
		return CertificateProfile{}, fmt.Errorf("%w: gateway identity is required", ErrInvalidCSR)
	}
	organizationID := strings.TrimSpace(gateway.TenantID)
	gatewayID := strings.TrimSpace(gateway.ID)
	fqdn := strings.TrimSpace(gateway.FQDN)
	if organizationID == "" || gatewayID == "" {
		return CertificateProfile{}, fmt.Errorf("%w: gateway organization_id and gateway_id are required", ErrInvalidCSR)
	}
	if fqdn == "" {
		return CertificateProfile{}, fmt.Errorf("%w: gateway FQDN is required before certificate issuance", ErrInvalidRequest)
	}
	return CertificateProfile{
		CommonName: fqdn,
		DNSNames:   []string{fqdn},
		URISANs:    []string{GatewayIdentityURI(organizationID, gatewayID)},
	}, nil
}

func validateGatewayCSRRequest(csr *x509.CertificateRequest, gateway *models.Gateway, fqdn string) error {
	if csr == nil || gateway == nil {
		return fmt.Errorf("%w: CSR and gateway identity are required", ErrInvalidCSR)
	}
	organizationID := strings.TrimSpace(gateway.TenantID)
	gatewayID := strings.TrimSpace(gateway.ID)
	if organizationID == "" || gatewayID == "" {
		return fmt.Errorf("%w: gateway organization_id and gateway_id are required", ErrInvalidCSR)
	}
	expectedURI := GatewayIdentityURI(organizationID, gatewayID)
	for _, identityURI := range csr.URIs {
		if identityURI != nil && identityURI.String() != expectedURI {
			return fmt.Errorf("%w: CSR URI SAN must not request a gateway identity other than %q", ErrInvalidCSR, expectedURI)
		}
	}
	fqdn = strings.TrimSpace(fqdn)
	for _, name := range csr.DNSNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if fqdn == "" || !strings.EqualFold(name, fqdn) {
			return fmt.Errorf("%w: CSR DNS SAN must not request a gateway FQDN other than %q", ErrInvalidCSR, fqdn)
		}
	}
	if len(csr.IPAddresses) > 0 {
		return fmt.Errorf("%w: gateway CSR must not request IP SANs", ErrInvalidCSR)
	}
	if len(csr.EmailAddresses) > 0 {
		return fmt.Errorf("%w: gateway CSR must not request email SANs", ErrInvalidCSR)
	}
	return nil
}

func validateGatewayCertificate(certPEM []byte, csr *x509.CertificateRequest, gateway *models.Gateway) error {
	cert, err := parseLeafCertificate(certPEM)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if cert.IsCA {
		return fmt.Errorf("%w: issued gateway certificate must not be a CA", ErrInvalidCSR)
	}
	if !certificateHasGatewayIdentity(cert, gateway.TenantID, gateway.ID) {
		return fmt.Errorf("%w: issued certificate does not contain expected gateway URI SAN", ErrInvalidCSR)
	}
	if fqdn := strings.TrimSpace(gateway.FQDN); fqdn != "" && !stringSliceContainsFold(cert.DNSNames, fqdn) {
		return fmt.Errorf("%w: issued certificate does not contain expected gateway DNS SAN", ErrInvalidCSR)
	}
	if !publicKeysEqual(cert.PublicKey, csr.PublicKey) {
		return fmt.Errorf("%w: issued certificate public key does not match CSR", ErrInvalidCSR)
	}
	if !extKeyUsageContains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return fmt.Errorf("%w: issued gateway certificate must allow server authentication", ErrInvalidCSR)
	}
	if !extKeyUsageContains(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return fmt.Errorf("%w: issued gateway certificate must allow client authentication", ErrInvalidCSR)
	}
	return nil
}

func parseLeafCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate PEM is invalid")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func publicKeysEqual(left, right interface{}) bool {
	leftDER, err := x509.MarshalPKIXPublicKey(left)
	if err != nil {
		return false
	}
	rightDER, err := x509.MarshalPKIXPublicKey(right)
	if err != nil {
		return false
	}
	return bytes.Equal(leftDER, rightDER)
}

func extKeyUsageContains(usages []x509.ExtKeyUsage, expected x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == expected {
			return true
		}
	}
	return false
}

func stringSliceContainsFold(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), expected) {
			return true
		}
	}
	return false
}

func certificateIdentity(certPEM []byte) (string, string) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", ""
	}
	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:]), cert.SerialNumber.String()
}

func randomHex(bytesLen int) (string, error) {
	if bytesLen <= 0 {
		return "", fmt.Errorf("random byte length must be positive")
	}
	randomBytes := make([]byte, bytesLen)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(randomBytes), nil
}

func gatewayListItem(gateway *models.Gateway) GatewayListItem {
	return GatewayListItem{
		ID:                gateway.ID,
		TenantID:          gateway.TenantID,
		Name:              gateway.Name,
		FQDN:              gateway.FQDN,
		Status:            gateway.Status,
		ListenAddr:        gateway.ListenAddr,
		PublicIP:          gateway.PublicIP,
		OIDCClientID:      gateway.OIDCClientID,
		EnrollmentToken:   "", // Never expose token hash — admin gets plaintext at creation only
		TokenExpiresAt:    gateway.TokenExpiresAt,
		CertExpiresAt:     gateway.CertExpiresAt,
		AssignedResources: append([]string(nil), gateway.AssignedResources...),
		AuthMode:          defaultGatewayAuthMode,
		CreatedAt:         gateway.CreatedAt,
		UpdatedAt:         gateway.UpdatedAt,
		LastSeenAt:        gateway.LastSeenAt,
	}
}

func sanitizeGatewayForAdmin(gateway *models.Gateway) *models.Gateway {
	if gateway == nil {
		return nil
	}
	copy := *gateway
	copy.AssignedResources = append([]string(nil), gateway.AssignedResources...)
	copy.TenantIDs = append([]string(nil), gateway.TenantIDs...)
	copy.EnrollmentToken = "" // Never expose token hash — defense in depth
	copy.OIDCClientSecret = ""
	copy.CertPEM = ""
	copy.AuthMode = defaultGatewayAuthMode
	copy.FederationConfig = nil
	return &copy
}

func gatewaySubjectID(gatewayID string) string {
	return "gateway:" + gatewayID
}
