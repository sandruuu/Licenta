package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

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
