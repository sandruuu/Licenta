package ipc

import "time"

type PingRequest struct {
	Message     string    `json:"message"`
	TrayPID     int       `json:"tray_pid"`
	TrayUser    string    `json:"tray_user,omitempty"`
	TrayUserSID string    `json:"tray_user_sid,omitempty"`
	SentAt      time.Time `json:"sent_at"`
}

type PingResponse struct {
	Message           string    `json:"message"`
	Echo              string    `json:"echo"`
	Protocol          string    `json:"protocol"`
	PipeName          string    `json:"pipe_name"`
	ServiceState      string    `json:"service_state"`
	ServicePID        int       `json:"service_pid"`
	ServiceUser       string    `json:"service_user,omitempty"`
	ServiceUserSID    string    `json:"service_user_sid,omitempty"`
	AuthorizedUserSID string    `json:"authorized_user_sid,omitempty"`
	ReceivedAt        time.Time `json:"received_at"`
}

type StatusRequest struct{}

type DashboardRequest struct{}

type CatalogResourcesRequest struct{}

type ActiveSessionsRequest struct{}

type AccessEventsRequest struct{}

type AgentStatus struct {
	ServiceState             string          `json:"service_state"`
	ServicePID               int             `json:"service_pid"`
	ServiceUser              string          `json:"service_user,omitempty"`
	ServiceUserSID           string          `json:"service_user_sid,omitempty"`
	AuthorizedUserSID        string          `json:"authorized_user_sid,omitempty"`
	EnrollmentState          EnrollmentState `json:"enrollment_state"`
	DeviceID                 string          `json:"device_id,omitempty"`
	DeviceIDSource           string          `json:"device_id_source,omitempty"`
	ActiveUserSID            string          `json:"active_user_sid,omitempty"`
	KeyName                  string          `json:"key_name,omitempty"`
	KeyExists                bool            `json:"key_exists"`
	KeyProvider              string          `json:"key_provider,omitempty"`
	EnrollmentNonce          string          `json:"enrollment_nonce,omitempty"`
	CertificateSHA256        string          `json:"certificate_sha256,omitempty"`
	CertificateExpiresAt     time.Time       `json:"certificate_expires_at,omitempty"`
	DevicePostureStatus      string          `json:"device_posture_status,omitempty"`
	DevicePostureCheckCount  int             `json:"device_posture_check_count,omitempty"`
	DevicePostureCollectedAt time.Time       `json:"device_posture_collected_at,omitempty"`
	DevicePostureReportedAt  time.Time       `json:"device_posture_reported_at,omitempty"`
	DevicePostureLastError   string          `json:"device_posture_last_error,omitempty"`
	DevicePostureReportError string          `json:"device_posture_report_error,omitempty"`
	SessionState             string          `json:"session_state,omitempty"`
	AccessTokenExpiresAt     time.Time       `json:"access_token_expires_at,omitempty"`
	CatalogStatus            string          `json:"catalog_status,omitempty"`
	CatalogVersion           string          `json:"catalog_version,omitempty"`
	CatalogPolicyEpoch       string          `json:"catalog_policy_epoch,omitempty"`
	CatalogDNSSuffixCount    int             `json:"catalog_dns_suffix_count,omitempty"`
	CatalogResourceCount     int             `json:"catalog_resource_count,omitempty"`
	CatalogLastSyncedAt      time.Time       `json:"catalog_last_synced_at,omitempty"`
	CatalogNextSyncAt        time.Time       `json:"catalog_next_sync_at,omitempty"`
	CatalogNextRetryAt       time.Time       `json:"catalog_next_retry_at,omitempty"`
	CatalogLastError         string          `json:"catalog_last_error,omitempty"`
	SyntheticDNSStatus       string          `json:"synthetic_dns_status,omitempty"`
	SyntheticDNSSuffixCount  int             `json:"synthetic_dns_suffix_count,omitempty"`
	SyntheticResourceCount   int             `json:"synthetic_resource_count,omitempty"`
	SyntheticMappingCount    int             `json:"synthetic_mapping_count,omitempty"`
	SyntheticCGNATRange      string          `json:"synthetic_cgnat_range,omitempty"`
	SyntheticDNSUpdatedAt    time.Time       `json:"synthetic_dns_updated_at,omitempty"`
	SyntheticDNSLastError    string          `json:"synthetic_dns_last_error,omitempty"`
	NetworkStatus            string          `json:"network_status,omitempty"`
	TUNName                  string          `json:"tun_name,omitempty"`
	TUNIP                    string          `json:"tun_ip,omitempty"`
	TUNNetmask               string          `json:"tun_netmask,omitempty"`
	TUNRouteCIDR             string          `json:"tun_route_cidr,omitempty"`
	NetworkUpdatedAt         time.Time       `json:"network_updated_at,omitempty"`
	NetworkPacketsRead       int64           `json:"network_packets_read,omitempty"`
	NetworkTCPPackets        int64           `json:"network_tcp_packets,omitempty"`
	NetworkMatchedPackets    int64           `json:"network_matched_packets,omitempty"`
	NetworkUnmatchedPackets  int64           `json:"network_unmatched_packets,omitempty"`
	NetworkDroppedPackets    int64           `json:"network_dropped_packets,omitempty"`
	NetworkForwarderReady    bool            `json:"network_forwarder_ready"`
	NetworkLastPacketAt      time.Time       `json:"network_last_packet_at,omitempty"`
	NetworkLastPacketError   string          `json:"network_last_packet_error,omitempty"`
	NetworkLastError         string          `json:"network_last_error,omitempty"`
	GatewayTunnelStatus      string          `json:"gateway_tunnel_status,omitempty"`
	GatewayAddress           string          `json:"gateway_address,omitempty"`
	GatewayTunnelConnectedAt time.Time       `json:"gateway_tunnel_connected_at,omitempty"`
	GatewayTunnelUpdatedAt   time.Time       `json:"gateway_tunnel_updated_at,omitempty"`
	GatewayTunnelLastError   string          `json:"gateway_tunnel_last_error,omitempty"`
	GatewayTunnelStreamCount int64           `json:"gateway_tunnel_stream_count,omitempty"`
	LastError                string          `json:"last_error,omitempty"`
	IdentityError            string          `json:"identity_error,omitempty"`
	IdentityCheckedAt        time.Time       `json:"identity_checked_at,omitempty"`
	ReportedAt               time.Time       `json:"reported_at"`
}
