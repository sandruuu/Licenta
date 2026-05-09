package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ProtocolVersion = "ztna-agent-ipc.v1"
	PipeName        = `\\.\pipe\ztna-agent`
	MaxMessageBytes = 1 << 20
)

type Operation string

const (
	OperationPing                  Operation = "Ping"
	OperationGetStatus             Operation = "GetStatus"
	OperationGetDashboard          Operation = "GetDashboard"
	OperationGetCatalogResources   Operation = "GetCatalogResources"
	OperationGetActiveSessions     Operation = "GetActiveSessions"
	OperationGetAccessEvents       Operation = "GetAccessEvents"
	OperationGetDevicePosture      Operation = "GetDevicePosture"
	OperationSubmitEnrollmentToken Operation = "SubmitEnrollmentToken"
	OperationUpdateAccessToken     Operation = "UpdateAccessToken"
)

type EnrollmentState string

const (
	EnrollmentStateUnknown    EnrollmentState = "UNKNOWN"
	EnrollmentStateUnenrolled EnrollmentState = "UNENROLLED"
	EnrollmentStatePending    EnrollmentState = "PENDING"
	EnrollmentStateEnrolled   EnrollmentState = "ENROLLED"
	EnrollmentStateFailed     EnrollmentState = "FAILED"
)

type Request struct {
	Version   string          `json:"version"`
	ID        string          `json:"id"`
	Operation Operation       `json:"operation"`
	Body      json.RawMessage `json:"body,omitempty"`
}

type Response struct {
	Version string          `json:"version"`
	ID      string          `json:"id"`
	OK      bool            `json:"ok"`
	Body    json.RawMessage `json:"body,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

const (
	ErrorCodeInvalidRequest     = "invalid_request"
	ErrorCodeUnsupported        = "unsupported_operation"
	ErrorCodeInternal           = "internal_error"
	ErrorCodeRateLimited        = "rate_limited"
	ErrorCodeServiceUnavailable = "service_unavailable"
)

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

type DevicePostureRequest struct{}

const (
	DevicePostureStatusGood        = "good"
	DevicePostureStatusWarning     = "warning"
	DevicePostureStatusCritical    = "critical"
	DevicePostureStatusUnavailable = "unavailable"
)

type DevicePostureReport struct {
	DeviceID    string               `json:"device_id,omitempty"`
	Hostname    string               `json:"hostname"`
	OS          string               `json:"os"`
	Checks      []DevicePostureCheck `json:"checks"`
	CollectedAt time.Time            `json:"collected_at"`
}

type DevicePostureCheck struct {
	Name        string            `json:"name"`
	Status      string            `json:"status"`
	Description string            `json:"description"`
	Details     map[string]string `json:"details,omitempty"`
}

type AgentDashboard struct {
	Connection     DashboardConnection `json:"connection"`
	Status         AgentStatus         `json:"status"`
	Enrollment     EnrollmentInfo      `json:"enrollment"`
	Certificate    CertificateInfo     `json:"certificate"`
	User           AuthenticatedUser   `json:"user"`
	Posture        DevicePostureReport `json:"posture"`
	Resources      []CatalogResource   `json:"resources"`
	ActiveSessions []ActiveSession     `json:"active_sessions"`
	AccessEvents   []AccessEvent       `json:"access_events"`
	ReportedAt     time.Time           `json:"reported_at"`
}

type DashboardConnection struct {
	State        string `json:"state"`
	Message      string `json:"message,omitempty"`
	ServiceState string `json:"service_state,omitempty"`
	SessionState string `json:"session_state,omitempty"`
	CatalogState string `json:"catalog_state,omitempty"`
	NetworkState string `json:"network_state,omitempty"`
}

type EnrollmentInfo struct {
	State          EnrollmentState `json:"state"`
	DeviceID       string          `json:"device_id,omitempty"`
	DeviceIDSource string          `json:"device_id_source,omitempty"`
	ActiveUserSID  string          `json:"active_user_sid,omitempty"`
	KeyName        string          `json:"key_name,omitempty"`
	KeyExists      bool            `json:"key_exists"`
	KeyProvider    string          `json:"key_provider,omitempty"`
	Nonce          string          `json:"nonce,omitempty"`
	LastError      string          `json:"last_error,omitempty"`
}

type CertificateInfo struct {
	SHA256       string    `json:"sha256,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	SerialNumber string    `json:"serial_number,omitempty"`
	NotBefore    time.Time `json:"not_before,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Valid        bool      `json:"valid"`
	LastError    string    `json:"last_error,omitempty"`
}

type AuthenticatedUser struct {
	UserSID              string    `json:"user_sid,omitempty"`
	AuthorizedUserSID    string    `json:"authorized_user_sid,omitempty"`
	Email                string    `json:"email,omitempty"`
	SessionState         string    `json:"session_state,omitempty"`
	AccessTokenExpiresAt time.Time `json:"access_token_expires_at,omitempty"`
}

type CatalogResource struct {
	FQDN       string    `json:"fqdn"`
	ResourceID string    `json:"resource_id,omitempty"`
	Protocol   string    `json:"protocol,omitempty"`
	Port       int       `json:"port,omitempty"`
	Status     string    `json:"status,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
}

type CatalogResourcesResponse struct {
	Resources  []CatalogResource `json:"resources"`
	ReportedAt time.Time         `json:"reported_at"`
}

type ActiveSession struct {
	ID         string    `json:"id"`
	ResourceID string    `json:"resource_id,omitempty"`
	FQDN       string    `json:"fqdn,omitempty"`
	Protocol   string    `json:"protocol,omitempty"`
	Port       int       `json:"port,omitempty"`
	State      string    `json:"state"`
	UserSID    string    `json:"user_sid,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	BytesIn    int64     `json:"bytes_in,omitempty"`
	BytesOut   int64     `json:"bytes_out,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
}

type ActiveSessionsResponse struct {
	Sessions   []ActiveSession `json:"sessions"`
	ReportedAt time.Time       `json:"reported_at"`
}

type AccessEvent struct {
	ID         string            `json:"id"`
	Decision   string            `json:"decision"`
	Reason     string            `json:"reason"`
	Source     string            `json:"source,omitempty"`
	ResourceID string            `json:"resource_id,omitempty"`
	FQDN       string            `json:"fqdn,omitempty"`
	Protocol   string            `json:"protocol,omitempty"`
	Port       int               `json:"port,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
	OccurredAt time.Time         `json:"occurred_at"`
}

type AccessEventsResponse struct {
	Events     []AccessEvent `json:"events"`
	ReportedAt time.Time     `json:"reported_at"`
}

type SubmitEnrollmentTokenRequest struct {
	Token                string    `json:"token"`
	AccessToken          string    `json:"access_token,omitempty"`
	AccessTokenExpiresAt time.Time `json:"access_token_expires_at,omitempty"`
	Nonce                string    `json:"nonce"`
	DeviceID             string    `json:"device_id"`
	UserSID              string    `json:"user_sid"`
	KeyName              string    `json:"key_name"`
	UserEmail            string    `json:"user_email,omitempty"`
	ExpiresAt            time.Time `json:"expires_at,omitempty"`
	ExpiresInSeconds     int       `json:"expires_in,omitempty"`
	SentAt               time.Time `json:"sent_at"`
}

type SubmitEnrollmentTokenResponse struct {
	Accepted        bool            `json:"accepted"`
	Message         string          `json:"message,omitempty"`
	DeviceID        string          `json:"device_id,omitempty"`
	ActiveUserSID   string          `json:"active_user_sid,omitempty"`
	KeyName         string          `json:"key_name,omitempty"`
	ReceivedAt      time.Time       `json:"received_at"`
	EnrollmentState EnrollmentState `json:"enrollment_state"`
}

type UpdateAccessTokenRequest struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	DeviceID    string    `json:"device_id"`
	UserSID     string    `json:"user_sid"`
	SentAt      time.Time `json:"sent_at"`
}

type UpdateAccessTokenResponse struct {
	Accepted   bool      `json:"accepted"`
	DeviceID   string    `json:"device_id,omitempty"`
	UserSID    string    `json:"user_sid,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
	ReceivedAt time.Time `json:"received_at"`
}

func SupportedOperations() map[Operation]struct{} {
	return map[Operation]struct{}{
		OperationPing:                  {},
		OperationGetStatus:             {},
		OperationGetDashboard:          {},
		OperationGetCatalogResources:   {},
		OperationGetActiveSessions:     {},
		OperationGetAccessEvents:       {},
		OperationGetDevicePosture:      {},
		OperationSubmitEnrollmentToken: {},
		OperationUpdateAccessToken:     {},
	}
}

func NewRequest(identifier string, operation Operation, payload any) (*Request, error) {
	body, err := EncodeBody(payload)
	if err != nil {
		return nil, err
	}
	request := &Request{Version: ProtocolVersion, ID: strings.TrimSpace(identifier), Operation: operation, Body: body}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	return request, nil
}

func NewResponse(identifier string, payload any) (*Response, error) {
	body, err := EncodeBody(payload)
	if err != nil {
		return nil, err
	}
	return &Response{Version: ProtocolVersion, ID: strings.TrimSpace(identifier), OK: true, Body: body}, nil
}

func NewErrorResponse(identifier, code, message string) *Response {
	return &Response{Version: ProtocolVersion, ID: strings.TrimSpace(identifier), OK: false, Error: &Error{Code: strings.TrimSpace(code), Message: strings.TrimSpace(message)}}
}

func DecodeRequest(data []byte) (*Request, error) {
	if len(data) > MaxMessageBytes {
		return nil, fmt.Errorf("ipc message exceeds %d bytes", MaxMessageBytes)
	}
	var request Request
	if err := json.Unmarshal(data, &request); err != nil {
		return nil, fmt.Errorf("decode ipc request: %w", err)
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	return &request, nil
}

func DecodeResponse(data []byte) (*Response, error) {
	if len(data) > MaxMessageBytes {
		return nil, fmt.Errorf("ipc message exceeds %d bytes", MaxMessageBytes)
	}
	var response Response
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("decode ipc response: %w", err)
	}
	if err := response.Validate(); err != nil {
		return nil, err
	}
	return &response, nil
}

func (request *Request) Validate() error {
	if request == nil {
		return errors.New("ipc request is nil")
	}
	if request.Version != ProtocolVersion {
		return fmt.Errorf("unsupported ipc version %q", request.Version)
	}
	if strings.TrimSpace(request.ID) == "" {
		return errors.New("ipc request id is required")
	}
	if _, ok := SupportedOperations()[request.Operation]; !ok {
		return fmt.Errorf("unsupported ipc operation %q", request.Operation)
	}
	if len(request.Body) > MaxMessageBytes {
		return fmt.Errorf("ipc request body exceeds %d bytes", MaxMessageBytes)
	}
	return nil
}

func (response *Response) Validate() error {
	if response == nil {
		return errors.New("ipc response is nil")
	}
	if response.Version != ProtocolVersion {
		return fmt.Errorf("unsupported ipc version %q", response.Version)
	}
	if strings.TrimSpace(response.ID) == "" {
		return errors.New("ipc response id is required")
	}
	if len(response.Body) > MaxMessageBytes {
		return fmt.Errorf("ipc response body exceeds %d bytes", MaxMessageBytes)
	}
	if response.OK {
		if response.Error != nil {
			return errors.New("ipc response cannot be ok and include an error")
		}
		return nil
	}
	if response.Error == nil {
		return errors.New("ipc error response requires an error object")
	}
	if strings.TrimSpace(response.Error.Code) == "" || strings.TrimSpace(response.Error.Message) == "" {
		return errors.New("ipc error response requires code and message")
	}
	return nil
}

func EncodeBody(payload any) (json.RawMessage, error) {
	if payload == nil {
		return nil, nil
	}
	if rawMessage, ok := payload.(json.RawMessage); ok {
		return rawMessage, nil
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode ipc body: %w", err)
	}
	return data, nil
}

func DecodeBody(rawMessage json.RawMessage, target any) error {
	if len(rawMessage) == 0 {
		return nil
	}
	if target == nil {
		return errors.New("decode target is nil")
	}
	if err := json.Unmarshal(rawMessage, target); err != nil {
		return fmt.Errorf("decode ipc body: %w", err)
	}
	return nil
}

func PipePath() string {
	return PipeName
}
