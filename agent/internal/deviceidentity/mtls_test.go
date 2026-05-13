package deviceidentity

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"
	"time"
)

func TestSelectMachineCertificateMatchesDeviceURISAN(t *testing.T) {
	deviceID := "2050b1864ca3647164fea13ac86d759e7f8bfb5ede15e202cc0869aa12671972"
	deviceURI, err := url.Parse("spiffe://ztna.local/device/" + deviceID)
	if err != nil {
		t.Fatalf("parse URI: %v", err)
	}
	cert := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "ztna-device-2050b1864ca3647164fea13ac86d759e7f8bfb5ede15e202"},
		URIs:        []*url.URL{deviceURI},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	selected, err := selectMachineCertificate([]*x509.Certificate{cert}, deviceID, nil, time.Now())
	if err != nil {
		t.Fatalf("selectMachineCertificate returned error: %v", err)
	}
	if selected != cert {
		t.Fatalf("selected certificate mismatch")
	}
}
