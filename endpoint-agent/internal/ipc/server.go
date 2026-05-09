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

type HandlerFunc func(context.Context, *Request) (*Response, error)

func (handler HandlerFunc) HandleIPC(ctx context.Context, request *Request) (*Response, error) {
	return handler(ctx, request)
}

type EventWriter interface {
	SendEvent(*Event) error
}

type StreamHandler interface {
	HandleIPCStream(context.Context, *Request, EventWriter) error
}

type frameEventWriter struct {
	connection net.Conn
}

func (writer frameEventWriter) SendEvent(event *Event) error {
	if err := event.Validate(); err != nil {
		return err
	}
	return WriteJSON(writer.connection, event)
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
		if request.Operation == OperationStreamEvents {
			streamHandler, ok := handler.(StreamHandler)
			if !ok {
				response := NewErrorResponse(request.ID, ErrorCodeUnsupported, "ipc handler does not support event streaming")
				if err := WriteJSON(connection, response); err != nil {
					return err
				}
				continue
			}
			response, err := NewResponse(request.ID, CommandAck{Accepted: true, Message: "event stream opened"})
			if err != nil {
				return err
			}
			if err := WriteJSON(connection, response); err != nil {
				return err
			}
			if err := streamHandler.HandleIPCStream(ctx, request, frameEventWriter{connection: connection}); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			return nil
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
