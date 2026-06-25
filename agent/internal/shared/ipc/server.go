package ipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

type Handler interface {
	HandleIPC(context.Context, *Request) (*Response, error)
}

var (
	ipcMaxActiveConnections = 32
	ipcReadTimeout          = 30 * time.Second
	ipcWriteTimeout         = 10 * time.Second
)

func Serve(ctx context.Context, listener net.Listener, handler Handler) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if listener == nil {
		return errors.New("ipc listener is nil")
	}
	if handler == nil {
		return errors.New("ipc handler is nil")
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	limit := ipcMaxActiveConnections
	if limit <= 0 {
		limit = 1
	}
	activeConnections := make(chan struct{}, limit)

	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept ipc connection: %w", err)
		}
		select {
		case activeConnections <- struct{}{}:
		default:
			_ = connection.Close()
			continue
		}
		go func() {
			defer func() { <-activeConnections }()
			_ = ServeConn(ctx, connection, handler)
		}()
	}
}

func ServeConn(ctx context.Context, connection net.Conn, handler Handler) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if connection == nil {
		return errors.New("ipc connection is nil")
	}
	if handler == nil {
		return errors.New("ipc handler is nil")
	}
	ctx = contextWithPeerIdentity(ctx, connection)
	defer connection.Close()

	for {
		setIPCReadDeadline(connection)
		requestPayload, err := ReadFrame(connection)
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		request, err := DecodeRequest(requestPayload)
		if err != nil {
			response := NewErrorResponse("invalid", ErrorCodeInvalidRequest, err.Error())
			if writeErr := writeIPCResponse(connection, response); writeErr != nil {
				return writeErr
			}
			continue
		}
		response, err := handler.HandleIPC(ctx, request)
		if err != nil {
			response = NewErrorResponse(request.ID, ErrorCodeInternal, err.Error())
		} else if response == nil {
			response = NewErrorResponse(request.ID, ErrorCodeInternal, "ipc handler returned no response")
		}
		if err := response.Validate(); err != nil {
			response = NewErrorResponse(request.ID, ErrorCodeInternal, err.Error())
		}
		if err := writeIPCResponse(connection, response); err != nil {
			return err
		}
	}
}

func writeIPCResponse(connection net.Conn, response *Response) error {
	setIPCWriteDeadline(connection)
	return WriteJSON(connection, response)
}

func setIPCReadDeadline(connection net.Conn) {
	if ipcReadTimeout <= 0 {
		_ = connection.SetReadDeadline(time.Time{})
		return
	}
	_ = connection.SetReadDeadline(time.Now().Add(ipcReadTimeout))
}

func setIPCWriteDeadline(connection net.Conn) {
	if ipcWriteTimeout <= 0 {
		_ = connection.SetWriteDeadline(time.Time{})
		return
	}
	_ = connection.SetWriteDeadline(time.Now().Add(ipcWriteTimeout))
}
