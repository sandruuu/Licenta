package gateway

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
)

const gatewayIdentityTrustDomain = "gateway"

// GatewayIdentityURI is the stable certificate identity used for gateway mTLS.
// FQDN remains a network attribute; organization_id + gateway_id are the
// authorization boundary and the gateway instance identity.
func GatewayIdentityURI(organizationID, gatewayID string) string {
	organizationID = strings.TrimSpace(organizationID)
	gatewayID = strings.TrimSpace(gatewayID)
	if organizationID == "" || gatewayID == "" {
		return ""
	}
	return fmt.Sprintf("spiffe://%s/organization/%s/gateway/%s",
		gatewayIdentityTrustDomain,
		url.PathEscape(organizationID),
		url.PathEscape(gatewayID),
	)
}

// GatewayCertificateIdentity extracts organization_id and gateway_id from the
// gateway URI SAN. It intentionally ignores CommonName because CN/FQDN is
// mutable and ambiguous across organizations.
func GatewayCertificateIdentity(cert *x509.Certificate) (organizationID, gatewayID string, ok bool) {
	if cert == nil {
		return "", "", false
	}
	for _, identityURI := range cert.URIs {
		organizationID, gatewayID, ok = parseGatewayIdentityURI(identityURI)
		if ok {
			return organizationID, gatewayID, true
		}
	}
	return "", "", false
}

func certificateHasGatewayIdentity(cert *x509.Certificate, organizationID, gatewayID string) bool {
	if cert == nil {
		return false
	}
	expectedOrganizationID := strings.TrimSpace(organizationID)
	expectedGatewayID := strings.TrimSpace(gatewayID)
	actualOrganizationID, actualGatewayID, ok := GatewayCertificateIdentity(cert)
	return ok && actualOrganizationID == expectedOrganizationID && actualGatewayID == expectedGatewayID
}

func parseGatewayIdentityURI(identityURI *url.URL) (organizationID, gatewayID string, ok bool) {
	if identityURI == nil {
		return "", "", false
	}
	if identityURI.Scheme != "spiffe" || identityURI.Host != gatewayIdentityTrustDomain {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(identityURI.EscapedPath(), "/"), "/")
	if len(parts) != 4 || parts[0] != "organization" || parts[2] != "gateway" {
		return "", "", false
	}
	organizationID, err := url.PathUnescape(parts[1])
	if err != nil {
		return "", "", false
	}
	gatewayID, err = url.PathUnescape(parts[3])
	if err != nil {
		return "", "", false
	}
	organizationID = strings.TrimSpace(organizationID)
	gatewayID = strings.TrimSpace(gatewayID)
	if organizationID == "" || gatewayID == "" {
		return "", "", false
	}
	return organizationID, gatewayID, true
}
