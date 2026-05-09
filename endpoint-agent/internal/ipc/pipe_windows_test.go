//go:build windows

package ipc

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"strings"
	"testing"
	"time"
)

func TestWindowsNamedPipeClientServerRoundTrip(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	if !strings.HasPrefix(currentUser.Uid, "S-1-") {
		t.Fatalf("current user uid %q is not a Windows SID", currentUser.Uid)
	}
	pipePath := fmt.Sprintf(`\\.\pipe\ztna-device-agent-test-%d`, time.Now().UTC().UnixNano())
	listener, err := ListenAt(pipePath, currentUser.Uid)
	if err != nil {
		t.Fatalf("ListenAt returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- Serve(ctx, listener, HandlerFunc(func(ctx context.Context, request *Request) (*Response, error) {
			return NewResponse(request.ID, DeviceAgentStatus{State: "running"})
		}))
	}()

	client := NewClient(func(ctx context.Context) (net.Conn, error) {
		return DialPath(ctx, pipePath)
	})
	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	var status DeviceAgentStatus
	if err := client.Call(callCtx, OperationGetStatus, nil, &status); err != nil {
		t.Fatalf("Call returned error: %v", err)
	}
	if status.State != "running" {
		t.Fatalf("state = %q, want running", status.State)
	}
	cancel()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("IPC server did not stop")
	}
}
