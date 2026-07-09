//go:build windows

package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const pipeDialRetryInterval = 150 * time.Millisecond

func Listen() (net.Listener, error) {
	return ListenForUserSID("")
}

func ListenForUserSID(authorizedUserSID string) (net.Listener, error) {
	return ListenAtForUserSID(PipePath(), authorizedUserSID)
}

func ListenAt(pipePath string) (net.Listener, error) {
	return ListenAtForUserSID(pipePath, "")
}

func ListenAtForUserSID(pipePath string, authorizedUserSID string) (net.Listener, error) {
	securityDescriptor, err := PipeSecurityDescriptor(authorizedUserSID)
	if err != nil {
		return nil, fmt.Errorf("build named pipe security descriptor: %w", err)
	}
	listener, err := winio.ListenPipe(pipePath, &winio.PipeConfig{
		MessageMode:        true,
		InputBufferSize:    MaxMessageBytes,
		OutputBufferSize:   MaxMessageBytes,
		SecurityDescriptor: securityDescriptor,
	})
	if err != nil {
		return nil, fmt.Errorf("listen on named pipe %s: %w", pipePath, err)
	}
	return listener, nil
}

func Dial(ctx context.Context) (net.Conn, error) {
	return DialPath(ctx, PipePath())
}

func DialPath(ctx context.Context, pipePath string) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	dialCtx := ctx
	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		dialCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	var lastErr error
	for {
		connection, err := winio.DialPipeContext(dialCtx, pipePath)
		if err == nil {
			return connection, nil
		}
		lastErr = err
		if dialCtx.Err() != nil || !isPipeNotReadyError(err) {
			return nil, fmt.Errorf("dial named pipe %s: %w", pipePath, err)
		}

		timer := time.NewTimer(pipeDialRetryInterval)
		select {
		case <-dialCtx.Done():
			timer.Stop()
			return nil, fmt.Errorf("dial named pipe %s: %w", pipePath, lastErr)
		case <-timer.C:
		}
	}
}

func isPipeNotReadyError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "cannot find the file specified") ||
		strings.Contains(message, "the system cannot find the file specified")
}
