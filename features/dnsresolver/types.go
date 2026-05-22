package dnsresolver

import "time"

const DefaultListenAddress = "127.0.0.1:53"

// Mapping is kept as a compatibility contract for dormant feature prototypes.
// The resolver implementation now lives in agent/internal/service/dns-resolver.
type Mapping struct {
	FQDN        string
	ResourceID  string
	Protocol    string
	Port        int
	SyntheticIP string
	CreatedAt   time.Time
	LastAccess  time.Time
	ExpiresAt   time.Time
}
