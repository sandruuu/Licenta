package ipc

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

type testHandlerFunc func(context.Context, *Request) (*Response, error)

func (handler testHandlerFunc) HandleIPC(ctx context.Context, request *Request) (*Response, error) {
	return handler(ctx, request)
}

func TestFrameRoundTrip(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteFrame(&buffer, []byte("hello")); err != nil {
		t.Fatalf("WriteFrame returned error: %v", err)
	}
	data, err := ReadFrame(&buffer)
	if err != nil {
		t.Fatalf("ReadFrame returned error: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("data = %q, want hello", data)
	}
}

func TestClientServerPingRoundTrip(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		_ = ServeConn(context.Background(), serverConn, testHandlerFunc(func(ctx context.Context, request *Request) (*Response, error) {
			var ping PingRequest
			if err := DecodeBody(request.Body, &ping); err != nil {
				return nil, err
			}
			return NewResponse(request.ID, PingResponse{Message: "pong", Echo: ping.Message, Protocol: ProtocolVersion})
		}))
	}()

	client := NewClient(func(context.Context) (net.Conn, error) { return clientConn, nil })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var response PingResponse
	if err := client.Call(ctx, OperationPing, PingRequest{Message: "hello", SentAt: time.Now().UTC()}, &response); err != nil {
		t.Fatalf("Call returned error: %v", err)
	}
	if response.Message != "pong" || response.Echo != "hello" || response.Protocol != ProtocolVersion {
		t.Fatalf("response = %+v", response)
	}
}
