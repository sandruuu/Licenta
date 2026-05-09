//go:build !windows

package ipc

import (
	"context"
	"fmt"
	"net"
)

func Listen(string) (net.Listener, error) {
	return nil, fmt.Errorf("Windows Named Pipes are only supported on Windows")
}

func Dial(context.Context) (net.Conn, error) {
	return nil, fmt.Errorf("Windows Named Pipes are only supported on Windows")
}
