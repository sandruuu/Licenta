package gateway

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
)

const gatewayIdentityTrustDomain = "ztna.local"

// GatewayIdentityURI is the stable certificate identity used for gateway mTLS.
// FQDN remains a network attribute; tenant_id + gateway_id are the authorization
// boundary and the gateway instance identity.
func GatewayIdentityURI(tenantID, gatewayID string) string {
	tenantID = strings.TrimSpace(tenantID)
	gatewayID = strings.TrimSpace(gatewayID)
	if tenantID == "" || gatewayID == "" {
		return ""
	}
	return fmt.Sprintf("spiffe://%s/tenant/%s/gateway/%s",
		gatewayIdentityTrustDomain,
		url.PathEscape(tenantID),
		url.PathEscape(gatewayID),
	)
}

// GatewayCertificateIdentity extracts tenant_id and gateway_id from the
// gateway URI SAN. It intentionally ignores CommonName because CN/FQDN is
// mutable and ambiguous across tenants.
func GatewayCertificateIdentity(cert *x509.Certificate) (tenantID, gatewayID string, ok bool) {
	if cert == nil {
		return "", "", false
	}
	for _, identityURI := range cert.URIs {
		tenantID, gatewayID, ok = parseGatewayIdentityURI(identityURI)
		if ok {
			return tenantID, gatewayID, true
		}
	}
	return "", "", false
}

func csrHasGatewayIdentity(csr *x509.CertificateRequest, tenantID, gatewayID string) bool {
	if csr == nil {
		return false
	}
	expected := GatewayIdentityURI(tenantID, gatewayID)
	if expected == "" {
		return false
	}
	for _, identityURI := range csr.URIs {
		if identityURI != nil && identityURI.String() == expected {
			return true
		}
	}
	return false
}

func certificateHasGatewayIdentity(cert *x509.Certificate, tenantID, gatewayID string) bool {
	if cert == nil {
		return false
	}
	expectedTenantID := strings.TrimSpace(tenantID)
	expectedGatewayID := strings.TrimSpace(gatewayID)
	actualTenantID, actualGatewayID, ok := GatewayCertificateIdentity(cert)
	return ok && actualTenantID == expectedTenantID && actualGatewayID == expectedGatewayID
}

func parseGatewayIdentityURI(identityURI *url.URL) (tenantID, gatewayID string, ok bool) {
	if identityURI == nil {
		return "", "", false
	}
	if identityURI.Scheme != "spiffe" || identityURI.Host != gatewayIdentityTrustDomain {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(identityURI.EscapedPath(), "/"), "/")
	if len(parts) != 4 || parts[0] != "tenant" || parts[2] != "gateway" {
		return "", "", false
	}
	tenantID, err := url.PathUnescape(parts[1])
	if err != nil {
		return "", "", false
	}
	gatewayID, err = url.PathUnescape(parts[3])
	if err != nil {
		return "", "", false
	}
	tenantID = strings.TrimSpace(tenantID)
	gatewayID = strings.TrimSpace(gatewayID)
	if tenantID == "" || gatewayID == "" {
		return "", "", false
	}
	return tenantID, gatewayID, true
}
