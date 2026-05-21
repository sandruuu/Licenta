package ipc

import "encoding/json"

const (
	ProtocolVersion = "trust-agent-ipc.v1"
	PipeName        = `\\.\pipe\trust-agent`
	MaxMessageBytes = 1 << 20
)

type Operation string

const (
	OperationPing                       Operation = "Ping"
	OperationGetStatus                  Operation = "GetStatus"
	OperationGetDashboard               Operation = "GetDashboard"
	OperationGetDevicePosture           Operation = "GetDevicePosture"
	OperationStartEnrollmentInteractive Operation = "StartEnrollmentInteractive"
	OperationStartUserLoginInteractive  Operation = "StartUserLoginInteractive"
	OperationLogoutUserSession          Operation = "LogoutUserSession"
)

type EnrollmentState string

const (
	EnrollmentStateUnenrolled EnrollmentState = "UNENROLLED"
	EnrollmentStateEnrolling  EnrollmentState = "ENROLLING"
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
	ErrorCodeServiceUnavailable = "service_unavailable"
)

func SupportedOperations() map[Operation]struct{} {
	return map[Operation]struct{}{
		OperationPing:                       {},
		OperationGetStatus:                  {},
		OperationGetDashboard:               {},
		OperationGetDevicePosture:           {},
		OperationStartEnrollmentInteractive: {},
		OperationStartUserLoginInteractive:  {},
		OperationLogoutUserSession:          {},
	}
}
