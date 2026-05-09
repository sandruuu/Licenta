package tray

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"ztna.local/agent/internal/ipc"
)

func TestTraySendsPing(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	oldNewDefaultClient := newDefaultClient
	newDefaultClient = func() *ipc.Client {
		return ipc.NewClient(func(context.Context) (net.Conn, error) { return clientConn, nil })
	}
	defer func() { newDefaultClient = oldNewDefaultClient }()

	go func() {
		_ = ipc.ServeConn(context.Background(), serverConn, ipc.HandlerFunc(func(ctx context.Context, request *ipc.Request) (*ipc.Response, error) {
			var ping ipc.PingRequest
			if err := ipc.DecodeBody(request.Body, &ping); err != nil {
				return nil, err
			}
			if ping.Message != "hello" {
				t.Errorf("message = %q, want hello", ping.Message)
			}
			return ipc.NewResponse(request.ID, ipc.PingResponse{Message: "pong", Echo: ping.Message, Protocol: ipc.ProtocolVersion})
		}))
	}()

	if err := Run(context.Background(), Options{Message: "hello", Timeout: time.Second}, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}
