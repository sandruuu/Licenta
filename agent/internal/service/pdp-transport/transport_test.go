package pdptransport

import (
	"crypto/tls"
	"testing"
)

func TestNewTLSConfigDefaultsToTLS13(t *testing.T) {
	tlsConfig, err := NewTLSConfig(Config{})
	if err != nil {
		t.Fatalf("NewTLSConfig failed: %v", err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", tlsConfig.MinVersion)
	}
}

func TestNewTLSConfigDoesNotDowngradeBelowTLS13(t *testing.T) {
	tlsConfig, err := NewTLSConfig(Config{MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("NewTLSConfig failed: %v", err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", tlsConfig.MinVersion)
	}
}
