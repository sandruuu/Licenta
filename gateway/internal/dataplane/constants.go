package dataplane

import "time"

const (
	agentListenAddr            = ":9443"
	relayDialTimeout           = 10 * time.Second
	maxConnections             = 1000
	maxConnectionsPerIP        = 100
	relayBufferSizeBytes       = 64 * 1024
	yamuxMaxStreamWindowSize   = 256 * 1024
	yamuxStreamOpenTimeout     = 30 * time.Second
	yamuxStreamCloseTimeout    = 5 * time.Minute
	revocationSyncInterval     = time.Minute
	sessionCleanupInterval     = time.Minute
	sessionRevalidationTimeout = 10 * time.Second
	certExpiryCheckInterval    = 12 * time.Hour
	certExpiryCriticalWindow   = 7 * 24 * time.Hour
	certExpiryWarningWindow    = 30 * 24 * time.Hour
	certRenewalCheckInterval   = 6 * time.Hour
	certRenewalWindow          = 48 * time.Hour
	maxRelayBandwidthMbps      = 400
)
