//go:build windows

package ipc

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"strings"
	"testing"
	"time"
)

func TestServeConnAttachesNamedPipePeerIdentity(t *testing.T) {
	currentSID := currentUserSID(t)
	if strings.TrimSpace(currentSID) == "" {
		t.Skip("current Windows user SID is unavailable")
	}
	pipePath := fmt.Sprintf(`\\.\pipe\trust-agent-test-%d-%d`, os.Getpid(), time.Now().UTC().UnixNano())
	listener, err := ListenAt(pipePath)
	if err != nil {
		t.Fatalf("ListenAt returned error: %v", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	identityCh := make(chan PeerIdentity, 1)
	go func() {
		_ = Serve(ctx, listener, testHandlerFunc(func(ctx context.Context, request *Request) (*Response, error) {
			identity, ok := PeerIdentityFromContext(ctx)
			if !ok {
				return NewErrorResponse(request.ID, ErrorCodeInternal, "missing peer identity"), nil
			}
			identityCh <- identity
			return NewResponse(request.ID, PingResponse{Message: "pong", Protocol: ProtocolVersion})
		}))
	}()

	client := NewClient(func(ctx context.Context) (net.Conn, error) {
		return DialPath(ctx, pipePath)
	})
	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	var response PingResponse
	if err := client.Call(callCtx, OperationPing, PingRequest{Message: "hello", SentAt: time.Now().UTC()}, &response); err != nil {
		t.Fatalf("Call returned error: %v", err)
	}
	select {
	case identity := <-identityCh:
		if !identity.Verified || !strings.EqualFold(identity.UserSID, currentSID) || identity.VerificationError != "" {
			t.Fatalf("peer identity = %+v, want verified SID %q", identity, currentSID)
		}
	case <-callCtx.Done():
		t.Fatal("timed out waiting for peer identity")
	}
}

func currentUserSID(t *testing.T) string {
	t.Helper()
	current, err := user.Current()
	if err != nil || current == nil {
		return ""
	}
	return strings.TrimSpace(current.Uid)
}
