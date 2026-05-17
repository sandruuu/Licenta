package ipc

import "encoding/json"

const (
	ProtocolVersion = "ztna-agent-ipc.v1"
	PipeName        = `\\.\pipe\ztna-agent`
	MaxMessageBytes = 1 << 20
)

type Operation string

const (
	OperationPing                Operation = "Ping"
	OperationGetStatus           Operation = "GetStatus"
	OperationGetDashboard        Operation = "GetDashboard"
	OperationGetCatalogResources Operation = "GetCatalogResources"
	OperationGetActiveSessions   Operation = "GetActiveSessions"
	OperationGetAccessEvents     Operation = "GetAccessEvents"
	OperationGetDevicePosture    Operation = "GetDevicePosture"
	OperationStartEnrollment     Operation = "StartEnrollment"
	OperationUpdateAccessToken   Operation = "UpdateAccessToken"
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

func SupportedOperations() map[Operation]struct{} {
	return map[Operation]struct{}{
		OperationPing:                {},
		OperationGetStatus:           {},
		OperationGetDashboard:        {},
		OperationGetCatalogResources: {},
		OperationGetActiveSessions:   {},
		OperationGetAccessEvents:     {},
		OperationGetDevicePosture:    {},
		OperationStartEnrollment:     {},
		OperationUpdateAccessToken:   {},
	}
}
