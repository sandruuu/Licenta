package gateway

import (
	"crypto/x509"
	"net/url"
	"testing"
)

func TestGatewayIdentityURIUsesOrganizationPath(t *testing.T) {
	got := GatewayIdentityURI("org-1", "gw-1")
	want := "spiffe://gateway/organization/org-1/gateway/gw-1"
	if got != want {
		t.Fatalf("GatewayIdentityURI() = %q, want %q", got, want)
	}
}

func TestGatewayCertificateIdentityRejectsTenantPath(t *testing.T) {
	identityURI, err := url.Parse("spiffe://gateway/tenant/tenant-1/gateway/gw-1")
	if err != nil {
		t.Fatalf("parse identity URI: %v", err)
	}
	if _, _, ok := GatewayCertificateIdentity(&x509.Certificate{URIs: []*url.URL{identityURI}}); ok {
		t.Fatal("GatewayCertificateIdentity() accepted legacy tenant identity")
	}
}

func TestGatewayCertificateIdentityReadsOrganizationPath(t *testing.T) {
	identityURI, err := url.Parse("spiffe://gateway/organization/org-1/gateway/gw-1")
	if err != nil {
		t.Fatalf("parse identity URI: %v", err)
	}
	organizationID, gatewayID, ok := GatewayCertificateIdentity(&x509.Certificate{URIs: []*url.URL{identityURI}})
	if !ok {
		t.Fatal("GatewayCertificateIdentity() rejected organization identity")
	}
	if organizationID != "org-1" || gatewayID != "gw-1" {
		t.Fatalf("GatewayCertificateIdentity() = organizationID=%q gatewayID=%q", organizationID, gatewayID)
	}
}
