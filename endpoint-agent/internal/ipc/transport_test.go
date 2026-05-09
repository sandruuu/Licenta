package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestClientServerCallRoundTrip(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- ServeConn(context.Background(), serverConn, HandlerFunc(func(ctx context.Context, request *Request) (*Response, error) {
			if request.Operation != OperationGetStatus {
				return nil, fmt.Errorf("operation = %q, want %q", request.Operation, OperationGetStatus)
			}
			return NewResponse(request.ID, DeviceAgentStatus{State: "running"})
		}))
	}()

	client := NewClient(func(ctx context.Context) (net.Conn, error) {
		return clientConn, nil
	})
	var status DeviceAgentStatus
	if err := client.Call(context.Background(), OperationGetStatus, nil, &status); err != nil {
		t.Fatalf("Call returned error: %v", err)
	}
	if status.State != "running" {
		t.Fatalf("state = %q, want running", status.State)
	}
}

func TestClientReturnsStructuredResponseError(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		_ = ServeConn(context.Background(), serverConn, HandlerFunc(func(ctx context.Context, request *Request) (*Response, error) {
			return NewErrorResponse(request.ID, ErrorCodeUnsupported, "streaming is not implemented yet"), nil
		}))
	}()

	client := NewClient(func(ctx context.Context) (net.Conn, error) {
		return clientConn, nil
	})
	var status DeviceAgentStatus
	err := client.Call(context.Background(), OperationGetStatus, nil, &status)
	if err == nil {
		t.Fatalf("Call returned nil error")
	}
	var responseError *ResponseError
	if !errors.As(err, &responseError) {
		t.Fatalf("error type = %T, want *ResponseError", err)
	}
	if responseError.Code != ErrorCodeUnsupported {
		t.Fatalf("code = %q, want %q", responseError.Code, ErrorCodeUnsupported)
	}
}

func TestClientStreamsEvents(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		_ = ServeConn(context.Background(), serverConn, testStreamHandler{})
	}()

	client := NewClient(func(ctx context.Context) (net.Conn, error) {
		return clientConn, nil
	})
	var eventType EventType
	if err := client.StreamEvents(context.Background(), func(event *Event) error {
		eventType = event.Type
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents returned error: %v", err)
	}
	if eventType != EventServiceStateChanged {
		t.Fatalf("event type = %q, want %q", eventType, EventServiceStateChanged)
	}
}

type testStreamHandler struct{}

func (testStreamHandler) HandleIPC(ctx context.Context, request *Request) (*Response, error) {
	return NewResponse(request.ID, DeviceAgentStatus{State: "running"})
}

func (testStreamHandler) HandleIPCStream(ctx context.Context, request *Request, writer EventWriter) error {
	event, err := NewEvent(EventServiceStateChanged, DeviceAgentStatus{State: "running"})
	if err != nil {
		return err
	}
	return writer.SendEvent(event)
}
