package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ProtocolVersion = "device-agent-ipc.v1"
	PipeName        = `\\.\pipe\ztna-device-agent`
	MaxMessageBytes = 1 << 20
)

type Operation string

const (
	OperationGetStatus             Operation = "GetStatus"
	OperationStreamEvents          Operation = "StreamEvents"
	OperationStartLogin            Operation = "StartLogin"
	OperationSubmitEnrollmentToken Operation = "SubmitEnrollmentToken"
	OperationRequestReconnect      Operation = "RequestReconnect"
	OperationGetHealthReport       Operation = "GetHealthReport"
	OperationGetNetworkState       Operation = "GetNetworkState"
	OperationGetDeviceIdentity     Operation = "GetDeviceIdentity"
)

type EventType string

const (
	EventServiceStateChanged EventType = "ServiceStateChanged"
	EventAuthStateChanged    EventType = "AuthStateChanged"
	EventEnrollmentChanged   EventType = "EnrollmentChanged"
	EventHealthUpdated       EventType = "HealthUpdated"
	EventNetworkChanged      EventType = "NetworkChanged"
	EventCatalogUpdated      EventType = "CatalogUpdated"
	EventNotification        EventType = "Notification"
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

type Event struct {
	Version string          `json:"version"`
	Type    EventType       `json:"type"`
	Time    time.Time       `json:"time"`
	Body    json.RawMessage `json:"body,omitempty"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

const (
	ErrorCodeInvalidRequest     = "invalid_request"
	ErrorCodeUnsupported        = "unsupported_operation"
	ErrorCodeInternal           = "internal_error"
	ErrorCodeServiceUnavailable = "service_unavailable"
)

type StartLoginRequest struct {
	AcrValues    string `json:"acr_values,omitempty"`
	Reason       string `json:"reason,omitempty"`
	ResourceFQDN string `json:"resource_fqdn,omitempty"`
}

type SubmitEnrollmentTokenRequest struct {
	Token     string `json:"token"`
	Nonce     string `json:"nonce,omitempty"`
	UserSID   string `json:"user_sid,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
}

type RequestReconnectRequest struct {
	Reason string `json:"reason,omitempty"`
}

type CommandAck struct {
	Accepted bool              `json:"accepted"`
	Message  string            `json:"message,omitempty"`
	Status   DeviceAgentStatus `json:"status"`
}

type DeviceAgentStatus struct {
	State             string    `json:"state"`
	DeviceID          string    `json:"device_id,omitempty"`
	Hostname          string    `json:"hostname,omitempty"`
	EnrolledUserSID   string    `json:"enrolled_user_sid,omitempty"`
	TPMBacked         bool      `json:"tpm_backed"`
	CertificateSource string    `json:"certificate_source,omitempty"`
	CatalogVersion    string    `json:"catalog_version,omitempty"`
	TunnelConnected   bool      `json:"tunnel_connected"`
	HealthScore       int       `json:"health_score,omitempty"`
	LastError         string    `json:"last_error,omitempty"`
	StartedAt         time.Time `json:"started_at,omitempty"`
	Capabilities      []string  `json:"capabilities,omitempty"`
}

type DeviceIdentity struct {
	DeviceID                 string `json:"device_id"`
	Hostname                 string `json:"hostname,omitempty"`
	UserEmail                string `json:"user_email,omitempty"`
	TPMBacked                bool   `json:"tpm_backed"`
	SoftwareFallbackReason   string `json:"software_fallback_reason,omitempty"`
	CertificateThumbprintSHA string `json:"certificate_thumbprint_sha256,omitempty"`
	CertificateStore         string `json:"certificate_store,omitempty"`
	CAStore                  string `json:"ca_store,omitempty"`
}

type HealthReport struct {
	DeviceID     string        `json:"device_id"`
	Hostname     string        `json:"hostname,omitempty"`
	OS           string        `json:"os,omitempty"`
	Checks       []HealthCheck `json:"checks,omitempty"`
	OverallScore int           `json:"overall_score"`
	CollectedAt  time.Time     `json:"collected_at"`
}

type HealthCheck struct {
	Name        string            `json:"name"`
	Status      string            `json:"status"`
	Description string            `json:"description,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
}

type NetworkState struct {
	TunnelConnected   bool      `json:"tunnel_connected"`
	Gateway           string    `json:"gateway,omitempty"`
	CatalogVersion    string    `json:"catalog_version,omitempty"`
	CatalogEntryCount int       `json:"catalog_entry_count,omitempty"`
	LastChangedAt     time.Time `json:"last_changed_at,omitempty"`
}

// CatalogUpdate is the event body for EventCatalogUpdated.
// It intentionally contains only version metadata — the FQDN list
// is private to the service process and is never exposed over IPC.
type CatalogUpdate struct {
	Version    string    `json:"version"`
	EntryCount int       `json:"entry_count"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func SupportedOperations() map[Operation]struct{} {
	return map[Operation]struct{}{
		OperationGetStatus:             {},
		OperationStreamEvents:          {},
		OperationStartLogin:            {},
		OperationSubmitEnrollmentToken: {},
		OperationRequestReconnect:      {},
		OperationGetHealthReport:       {},
		OperationGetNetworkState:       {},
		OperationGetDeviceIdentity:     {},
	}
}

func NewRequest(identifier string, operation Operation, payload any) (*Request, error) {
	body, err := EncodeBody(payload)
	if err != nil {
		return nil, err
	}
	request := &Request{
		Version:   ProtocolVersion,
		ID:        strings.TrimSpace(identifier),
		Operation: operation,
		Body:      body,
	}
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
	return &Response{
		Version: ProtocolVersion,
		ID:      strings.TrimSpace(identifier),
		OK:      false,
		Error: &Error{
			Code:    strings.TrimSpace(code),
			Message: strings.TrimSpace(message),
		},
	}
}

func NewEvent(eventType EventType, payload any) (*Event, error) {
	body, err := EncodeBody(payload)
	if err != nil {
		return nil, err
	}
	return &Event{Version: ProtocolVersion, Type: eventType, Time: time.Now().UTC(), Body: body}, nil
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

func DecodeEvent(data []byte) (*Event, error) {
	if len(data) > MaxMessageBytes {
		return nil, fmt.Errorf("ipc message exceeds %d bytes", MaxMessageBytes)
	}
	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, fmt.Errorf("decode ipc event: %w", err)
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}
	return &event, nil
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
	if strings.TrimSpace(response.Error.Code) == "" {
		return errors.New("ipc error response code is required")
	}
	if strings.TrimSpace(response.Error.Message) == "" {
		return errors.New("ipc error response message is required")
	}
	return nil
}

func (event *Event) Validate() error {
	if event == nil {
		return errors.New("ipc event is nil")
	}
	if event.Version != ProtocolVersion {
		return fmt.Errorf("unsupported ipc version %q", event.Version)
	}
	if strings.TrimSpace(string(event.Type)) == "" {
		return errors.New("ipc event type is required")
	}
	if event.Time.IsZero() {
		return errors.New("ipc event time is required")
	}
	if len(event.Body) > MaxMessageBytes {
		return fmt.Errorf("ipc event body exceeds %d bytes", MaxMessageBytes)
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
