package ipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
)

type Handler interface {
	HandleIPC(context.Context, *Request) (*Response, error)
}

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

	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept ipc connection: %w", err)
		}
		go func() {
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
			if writeErr := WriteJSON(connection, response); writeErr != nil {
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
		if err := WriteJSON(connection, response); err != nil {
			return err
		}
	}
}
