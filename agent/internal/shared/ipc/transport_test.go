package ipc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type testHandlerFunc func(context.Context, *Request) (*Response, error)

func (handler testHandlerFunc) HandleIPC(ctx context.Context, request *Request) (*Response, error) {
	return handler(ctx, request)
}

func TestFrameRoundTrip(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteFrame(&buffer, []byte("hello")); err != nil {
		t.Fatalf("WriteFrame returned error: %v", err)
	}
	data, err := ReadFrame(&buffer)
	if err != nil {
		t.Fatalf("ReadFrame returned error: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("data = %q, want hello", data)
	}
}

func TestClientServerPingRoundTrip(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		_ = ServeConn(context.Background(), serverConn, testHandlerFunc(func(ctx context.Context, request *Request) (*Response, error) {
			var ping PingRequest
			if err := DecodeBody(request.Body, &ping); err != nil {
				return nil, err
			}
			return NewResponse(request.ID, PingResponse{Message: "pong", Echo: ping.Message, Protocol: ProtocolVersion})
		}))
	}()

	client := NewClient(func(context.Context) (net.Conn, error) { return clientConn, nil })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var response PingResponse
	if err := client.Call(ctx, OperationPing, PingRequest{Message: "hello", SentAt: time.Now().UTC()}, &response); err != nil {
		t.Fatalf("Call returned error: %v", err)
	}
	if response.Message != "pong" || response.Echo != "hello" || response.Protocol != ProtocolVersion {
		t.Fatalf("response = %+v", response)
	}
}

func TestServeConnReturnsOnIdleReadDeadline(t *testing.T) {
	oldReadTimeout := ipcReadTimeout
	ipcReadTimeout = 20 * time.Millisecond
	defer func() { ipcReadTimeout = oldReadTimeout }()

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- ServeConn(context.Background(), serverConn, testHandlerFunc(func(ctx context.Context, request *Request) (*Response, error) {
			return NewResponse(request.ID, PingResponse{Message: "pong", Protocol: ProtocolVersion})
		}))
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("ServeConn returned nil, want read timeout")
		}
	case <-time.After(time.Second):
		t.Fatalf("ServeConn did not return after idle read deadline")
	}
}

func TestServeRejectsConnectionsOverLimit(t *testing.T) {
	oldLimit := ipcMaxActiveConnections
	oldReadTimeout := ipcReadTimeout
	ipcMaxActiveConnections = 1
	ipcReadTimeout = time.Second
	defer func() {
		ipcMaxActiveConnections = oldLimit
		ipcReadTimeout = oldReadTimeout
	}()

	listener := newTestListener()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, listener, testHandlerFunc(func(ctx context.Context, request *Request) (*Response, error) {
			return NewResponse(request.ID, PingResponse{Message: "pong", Protocol: ProtocolVersion})
		}))
	}()

	serverConn1, clientConn1 := net.Pipe()
	defer clientConn1.Close()
	listener.accept(serverConn1)

	serverConn2, clientConn2 := net.Pipe()
	defer clientConn2.Close()
	listener.accept(serverConn2)

	_ = clientConn2.SetReadDeadline(time.Now().Add(time.Second))
	var buf [1]byte
	_, err := clientConn2.Read(buf[:])
	if err == nil {
		t.Fatalf("second connection read succeeded, want closed connection")
	}
	if !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, io.EOF) && !isNetPipeClosedError(err) {
		t.Fatalf("second connection read error = %v, want closed connection", err)
	}

	_ = clientConn1.Close()
	cancel()
	_ = listener.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("Serve did not stop after context cancellation")
	}
}

type testListener struct {
	connections chan net.Conn
	closed      chan struct{}
}

func newTestListener() *testListener {
	return &testListener{
		connections: make(chan net.Conn, 4),
		closed:      make(chan struct{}),
	}
}

func (listener *testListener) Accept() (net.Conn, error) {
	select {
	case conn := <-listener.connections:
		return conn, nil
	case <-listener.closed:
		return nil, net.ErrClosed
	}
}

func (listener *testListener) Close() error {
	select {
	case <-listener.closed:
	default:
		close(listener.closed)
	}
	return nil
}

func (listener *testListener) Addr() net.Addr {
	return testAddr("ipc-test")
}

func (listener *testListener) accept(conn net.Conn) {
	select {
	case listener.connections <- conn:
	case <-time.After(time.Second):
		panic("test listener did not accept connection")
	}
}

type testAddr string

func (addr testAddr) Network() string { return string(addr) }
func (addr testAddr) String() string  { return string(addr) }

func isNetPipeClosedError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "closed pipe")
}
