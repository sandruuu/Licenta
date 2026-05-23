//go:build windows

package wfpcontrol

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

const (
	fileDeviceTrustAgentWFP uint32 = 0x8000
	methodBuffered          uint32 = 0
	fileAnyAccess           uint32 = 0

	ioctlApplyRules          = (fileDeviceTrustAgentWFP << 16) | (fileAnyAccess << 14) | (0x801 << 2) | methodBuffered
	ioctlClearRules          = (fileDeviceTrustAgentWFP << 16) | (fileAnyAccess << 14) | (0x802 << 2) | methodBuffered
	ioctlQueryOriginalTarget = (fileDeviceTrustAgentWFP << 16) | (fileAnyAccess << 14) | (0x803 << 2) | methodBuffered
)

type driverController struct {
	mu     sync.Mutex
	logger *slog.Logger
	config Config
	status Status
}

func NewController(config Config, logger *slog.Logger) Controller {
	if logger == nil {
		logger = slog.Default()
	}
	config.DevicePath = strings.TrimSpace(config.DevicePath)
	if config.DevicePath == "" {
		config.DevicePath = DefaultDevicePath
	}
	if !config.Enabled {
		return &disabledController{status: Status{State: StatusDisabled, DevicePath: config.DevicePath}}
	}
	return &driverController{
		logger: logger,
		config: config,
		status: Status{State: StatusDriverMissing, DevicePath: config.DevicePath},
	}
}

func (controller *driverController) ApplyRules(ctx context.Context, request ApplyRequest) error {
	if controller == nil {
		return errors.New("WFP controller is nil")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	payload, err := encodeApplyRequest(request)
	if err != nil {
		controller.setError(err, 0)
		return err
	}
	if _, err := controller.deviceIoControl(ioctlApplyRules, payload, nil); err != nil {
		err = fmt.Errorf("apply WFP redirect rules through %s: %w", controller.config.DevicePath, err)
		controller.setError(err, 0)
		return err
	}
	controller.mu.Lock()
	controller.status = Status{State: StatusReady, DevicePath: controller.config.DevicePath, RuleCount: len(request.Rules)}
	controller.mu.Unlock()
	return nil
}

func (controller *driverController) Clear(ctx context.Context) error {
	if controller == nil {
		return nil
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if _, err := controller.deviceIoControl(ioctlClearRules, nil, nil); err != nil {
		err = fmt.Errorf("clear WFP redirect rules through %s: %w", controller.config.DevicePath, err)
		controller.setError(err, controller.Status().RuleCount)
		return err
	}
	controller.mu.Lock()
	controller.status = Status{State: StatusReady, DevicePath: controller.config.DevicePath}
	controller.mu.Unlock()
	return nil
}

func (controller *driverController) ResolveOriginalDestination(ctx context.Context, conn net.Conn) (Destination, error) {
	if controller == nil {
		return Destination{}, errors.New("WFP controller is nil")
	}
	if err := contextError(ctx); err != nil {
		return Destination{}, err
	}
	if destination, err := queryRedirectContextFromSocket(conn); err == nil {
		return destination, nil
	}
	payload, err := encodeConnectionQuery(conn)
	if err != nil {
		return Destination{}, err
	}
	output := make([]byte, 64)
	bytesReturned, err := controller.deviceIoControl(ioctlQueryOriginalTarget, payload, output)
	if err != nil {
		err = fmt.Errorf("query WFP original destination through %s: %w", controller.config.DevicePath, err)
		controller.setError(err, controller.Status().RuleCount)
		return Destination{}, err
	}
	return decodeDestinationPayload(output[:bytesReturned])
}

func queryRedirectContextFromSocket(conn net.Conn) (Destination, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return Destination{}, fmt.Errorf("connection %q is not TCP", conn.LocalAddr())
	}
	rawConn, err := tcp.SyscallConn()
	if err != nil {
		return Destination{}, fmt.Errorf("get raw TCP socket: %w", err)
	}
	output := make([]byte, 64)
	var bytesReturned uint32
	var ioctlErr error
	controlErr := rawConn.Control(func(fd uintptr) {
		var outPtr *byte
		if len(output) > 0 {
			outPtr = &output[0]
		}
		ioctlErr = windows.WSAIoctl(
			windows.Handle(fd),
			sioQueryWFPConnectionRedirectContext,
			nil,
			0,
			outPtr,
			uint32(len(output)),
			&bytesReturned,
			nil,
			0,
		)
	})
	if controlErr != nil {
		return Destination{}, fmt.Errorf("control TCP socket: %w", controlErr)
	}
	if ioctlErr != nil {
		return Destination{}, fmt.Errorf("query WFP redirect context: %w", ioctlErr)
	}
	if bytesReturned == 0 {
		return Destination{}, errors.New("WFP redirect context is empty")
	}
	return decodeDestinationPayload(output[:bytesReturned])
}

func (controller *driverController) Status() Status {
	if controller == nil {
		return Status{State: StatusDriverMissing}
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.status
}

func (controller *driverController) deviceIoControl(code uint32, input []byte, output []byte) (uint32, error) {
	path, err := windows.UTF16PtrFromString(controller.config.DevicePath)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(
		path,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(handle)

	var inPtr *byte
	if len(input) > 0 {
		inPtr = &input[0]
	}
	var outPtr *byte
	if len(output) > 0 {
		outPtr = &output[0]
	}
	var bytesReturned uint32
	err = windows.DeviceIoControl(handle, code, inPtr, uint32(len(input)), outPtr, uint32(len(output)), &bytesReturned, nil)
	return bytesReturned, err
}

func (controller *driverController) setError(err error, ruleCount int) {
	if err == nil {
		return
	}
	controller.mu.Lock()
	controller.status = Status{
		State:      StatusError,
		DevicePath: controller.config.DevicePath,
		RuleCount:  ruleCount,
		LastError:  err.Error(),
	}
	controller.mu.Unlock()
	controller.logger.Warn("WFP controller error", "error", err)
}

type disabledController struct {
	status Status
}

func (controller *disabledController) ApplyRules(context.Context, ApplyRequest) error {
	return nil
}

func (controller *disabledController) Clear(context.Context) error {
	return nil
}

func (controller *disabledController) ResolveOriginalDestination(context.Context, net.Conn) (Destination, error) {
	return Destination{}, errors.New("WFP controller is disabled")
}

func (controller *disabledController) Status() Status {
	if controller == nil {
		return Status{State: StatusDisabled}
	}
	return controller.status
}

func encodeConnectionQuery(conn net.Conn) ([]byte, error) {
	if conn == nil {
		return nil, errors.New("connection is nil")
	}
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("local address %q is not TCP", conn.LocalAddr())
	}
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("remote address %q is not TCP", conn.RemoteAddr())
	}
	localIP := local.IP.To4()
	remoteIP := remote.IP.To4()
	if localIP == nil || remoteIP == nil {
		return nil, errors.New("WFP original destination query currently supports IPv4 TCP only")
	}
	buffer := new(bytes.Buffer)
	for _, value := range []any{
		payloadMagic,
		payloadVersion,
		uint16(0),
		binary.BigEndian.Uint32(localIP),
		uint16(local.Port),
		binary.BigEndian.Uint32(remoteIP),
		uint16(remote.Port),
		protocolTCP,
		uint8(0),
	} {
		if err := binary.Write(buffer, binary.LittleEndian, value); err != nil {
			return nil, err
		}
	}
	return buffer.Bytes(), nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

const (
	iocVendor uint32 = 0x18000000
	iocIn     uint32 = 0x80000000

	sioQueryWFPConnectionRedirectContext uint32 = iocIn | iocVendor | 221
)
