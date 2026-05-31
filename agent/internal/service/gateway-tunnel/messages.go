package gatewaytunnel

const (
	ProtocolVersion          = "1.0"
	ProtocolMinClientVersion = "1.0"
	ProtocolMaxClientVersion = "1.0"
)

const (
	CodeOK                      = "ok"
	CodeAuthRequired            = "auth_required"
	CodeAuthInvalid             = "auth_invalid"
	CodeStepUpRequired          = "step_up_required"
	CodePolicyDenied            = "policy_denied"
	CodeRiskDenied              = "risk_denied"
	CodeSessionInvalid          = "session_invalid"
	CodeSessionExpired          = "session_expired"
	CodeSessionStoreUnavailable = "session_store_unavailable"
	CodeTrustCloudUnreachable   = "trustcloud_unreachable"
	CodeRateLimited             = "rate_limited"
	CodeResourceUnknown         = "resource_unknown"
	CodeResourceUnavailable     = "resource_unavailable"
	CodeDNSNotFound             = "dns_not_found"
	CodeDNSResolveFailed        = "dns_resolve_failed"
	CodeInternalError           = "internal_error"
	CodeBadRequest              = "bad_request"
)

type HelloRequest struct {
	Type          string   `json:"type"`
	ClientVersion string   `json:"client_version"`
	ClientApp     string   `json:"client_app"`
	ClientBuild   string   `json:"client_build"`
	Features      []string `json:"features"`
}

type HelloResponse struct {
	Type             string   `json:"type"`
	Code             string   `json:"code"`
	ServerVersion    string   `json:"server_version"`
	MinClientVersion string   `json:"min_client_version"`
	MaxClientVersion string   `json:"max_client_version"`
	Features         []string `json:"features"`
	Message          string   `json:"message,omitempty"`
}

type ConnectRequest struct {
	Type         string           `json:"type"`
	RemoteAddr   string           `json:"remote_addr"`
	RemotePort   int              `json:"remote_port"`
	SessionID    string           `json:"session_id,omitempty"`
	SessionToken string           `json:"session_token,omitempty"`
	ResourceID   string           `json:"resource_id,omitempty"`
	Protocol     string           `json:"protocol,omitempty"`
	DeviceID     string           `json:"device_id,omitempty"`
	Process      *ProcessIdentity `json:"process,omitempty"`
}

type ConnectResponse struct {
	Type      string `json:"type"`
	Status    string `json:"status"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message"`
	ACRValues string `json:"acr_values,omitempty"`
}

type ProcessIdentity struct {
	PID    int    `json:"pid,omitempty"`
	Name   string `json:"name,omitempty"`
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Signer string `json:"signer,omitempty"`
}

type ResourceStreamRequest struct {
	TargetHost        string
	TargetPort        int
	SessionID         string
	SessionToken      string
	ResourceID        string
	Protocol          string
	GatewayID         string
	GatewayEndpoint   string
	GatewayServerName string
	Process           *ProcessIdentity
}
