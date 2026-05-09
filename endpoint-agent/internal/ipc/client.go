package ipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type Dialer func(context.Context) (net.Conn, error)

type Client struct {
	dialer Dialer
}

type ResponseError struct {
	Code    string
	Message string
}

func (responseError *ResponseError) Error() string {
	if responseError == nil {
		return "ipc response error"
	}
	return strings.TrimSpace(responseError.Code) + ": " + strings.TrimSpace(responseError.Message)
}

func NewClient(dialer Dialer) *Client {
	if dialer == nil {
		dialer = Dial
	}
	return &Client{dialer: dialer}
}

func NewDefaultClient() *Client {
	return NewClient(Dial)
}

func NewRequestID(prefix string) string {
	cleanPrefix := strings.TrimSpace(prefix)
	if cleanPrefix == "" {
		cleanPrefix = "req"
	}
	return fmt.Sprintf("%s-%d", cleanPrefix, time.Now().UTC().UnixNano())
}

func (client *Client) Call(ctx context.Context, operation Operation, payload any, target any) error {
	request, err := NewRequest(NewRequestID(strings.ToLower(string(operation))), operation, payload)
	if err != nil {
		return err
	}
	response, err := client.CallRequest(ctx, request)
	if err != nil {
		return err
	}
	if !response.OK {
		return &ResponseError{Code: response.Error.Code, Message: response.Error.Message}
	}
	return DecodeBody(response.Body, target)
}

func (client *Client) CallRequest(ctx context.Context, request *Request) (*Response, error) {
	if client == nil {
		return nil, fmt.Errorf("ipc client is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	connection, err := client.dialer(ctx)
	if err != nil {
		return nil, fmt.Errorf("dial device-agent ipc pipe: %w", err)
	}
	defer connection.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := WriteJSON(connection, request); err != nil {
		return nil, err
	}
	responsePayload, err := ReadFrame(connection)
	if err != nil {
		return nil, err
	}
	response, err := DecodeResponse(responsePayload)
	if err != nil {
		return nil, err
	}
	if response.ID != request.ID {
		return nil, fmt.Errorf("ipc response id %q does not match request id %q", response.ID, request.ID)
	}
	return response, nil
}

func (client *Client) StreamEvents(ctx context.Context, handleEvent func(*Event) error) error {
	if client == nil {
		return fmt.Errorf("ipc client is nil")
	}
	if handleEvent == nil {
		return fmt.Errorf("ipc event handler is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	request, err := NewRequest(NewRequestID("stream-events"), OperationStreamEvents, nil)
	if err != nil {
		return err
	}
	connection, err := client.dialer(ctx)
	if err != nil {
		return fmt.Errorf("dial device-agent ipc pipe: %w", err)
	}
	defer connection.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := WriteJSON(connection, request); err != nil {
		return err
	}
	ackPayload, err := ReadFrame(connection)
	if err != nil {
		return err
	}
	ack, err := DecodeResponse(ackPayload)
	if err != nil {
		return err
	}
	if ack.ID != request.ID {
		return fmt.Errorf("ipc response id %q does not match request id %q", ack.ID, request.ID)
	}
	if !ack.OK {
		return &ResponseError{Code: ack.Error.Code, Message: ack.Error.Message}
	}

	for {
		eventPayload, err := ReadFrame(connection)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		event, err := DecodeEvent(eventPayload)
		if err != nil {
			return err
		}
		if err := handleEvent(event); err != nil {
			return err
		}
	}
}
