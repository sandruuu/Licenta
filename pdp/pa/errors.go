package pa

import "errors"

type AccessErrorCode string

const (
	AccessErrorInvalidRequest     AccessErrorCode = "invalid_request"
	AccessErrorUnauthenticated    AccessErrorCode = "unauthenticated"
	AccessErrorPermissionDenied   AccessErrorCode = "permission_denied"
	AccessErrorNotFound           AccessErrorCode = "not_found"
	AccessErrorConflict           AccessErrorCode = "conflict"
	AccessErrorServiceUnavailable AccessErrorCode = "service_unavailable"
	AccessErrorInternal           AccessErrorCode = "internal"
)

type AccessError struct {
	Code    AccessErrorCode
	Message string
	Cause   error
}

func (err *AccessError) Error() string {
	if err == nil {
		return ""
	}
	if err.Message != "" {
		return err.Message
	}
	if err.Cause != nil {
		return err.Cause.Error()
	}
	return string(err.Code)
}

func (err *AccessError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

func newAccessError(code AccessErrorCode, message string, cause error) *AccessError {
	return &AccessError{Code: code, Message: message, Cause: cause}
}

func AccessErrorCodeOf(err error) AccessErrorCode {
	var accessErr *AccessError
	if errors.As(err, &accessErr) && accessErr.Code != "" {
		return accessErr.Code
	}
	return AccessErrorInternal
}
