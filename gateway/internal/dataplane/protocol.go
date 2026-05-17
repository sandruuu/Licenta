package dataplane

type ConnectRequest struct {
	Type         string           `json:"type"`
	RemoteAddr   string           `json:"remote_addr"`
	RemotePort   int              `json:"remote_port"`
	Token        string           `json:"token,omitempty"`
	SessionID    string           `json:"session_id,omitempty"`
	SessionToken string           `json:"session_token,omitempty"`
	ResourceID   string           `json:"resource_id,omitempty"`
	Protocol     string           `json:"protocol,omitempty"`
	DeviceID     string           `json:"device_id,omitempty"`
	Process      *ProcessIdentity `json:"process,omitempty"`
}

type ProcessIdentity struct {
	PID    int    `json:"pid,omitempty"`
	Name   string `json:"name,omitempty"`
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Signer string `json:"signer,omitempty"`
}

type ConnectResponse struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

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

const (
	ProtocolVersion          = "1.0"
	ProtocolMinClientVersion = "1.0"
	ProtocolMaxClientVersion = "1.0"
)

const (
	CodeOK                  = "ok"
	CodeAuthInvalid         = "auth_invalid"
	CodeSessionInvalid      = "session_invalid"
	CodeResourceUnavailable = "resource_unavailable"
	CodeInternalError       = "internal_error"
	CodeBadRequest          = "bad_request"
)
