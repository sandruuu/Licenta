//go:build windows

package ipc

import (
	"context"
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
)

func Listen() (net.Listener, error) {
	return ListenAt(PipePath())
}

func ListenAt(pipePath string) (net.Listener, error) {
	securityDescriptor, err := PipeSecurityDescriptor("")
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
	connection, err := winio.DialPipeContext(ctx, pipePath)
	if err != nil {
		return nil, fmt.Errorf("dial named pipe %s: %w", pipePath, err)
	}
	return connection, nil
}
