//go:build !windows

package ipc

import (
	"context"
	"errors"
	"net"
)

func Listen(enrolledUserSID string) (net.Listener, error) {
	return nil, errors.New("Windows Named Pipes IPC is unavailable on this platform")
}

func ListenAt(pipePath, enrolledUserSID string) (net.Listener, error) {
	return nil, errors.New("Windows Named Pipes IPC is unavailable on this platform")
}

func Dial(ctx context.Context) (net.Conn, error) {
	return nil, errors.New("Windows Named Pipes IPC is unavailable on this platform")
}

func DialPath(ctx context.Context, pipePath string) (net.Conn, error) {
	return nil, errors.New("Windows Named Pipes IPC is unavailable on this platform")
}
