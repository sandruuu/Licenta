//go:build !windows

package wfpcontrol

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
)

type unsupportedController struct {
	status Status
}

func NewController(config Config, _ *slog.Logger) Controller {
	config.DevicePath = strings.TrimSpace(config.DevicePath)
	if config.DevicePath == "" {
		config.DevicePath = DefaultDevicePath
	}
	state := StatusDisabled
	if config.Enabled {
		state = StatusDriverMissing
	}
	return &unsupportedController{status: Status{State: state, DevicePath: config.DevicePath, LastError: "WFP is supported only on Windows"}}
}

func (controller *unsupportedController) ApplyRules(context.Context, ApplyRequest) error {
	if controller == nil || controller.status.State == StatusDisabled {
		return nil
	}
	return errors.New("WFP is supported only on Windows")
}

func (controller *unsupportedController) Clear(context.Context) error {
	return nil
}

func (controller *unsupportedController) ResolveOriginalDestination(context.Context, net.Conn) (Destination, error) {
	return Destination{}, errors.New("WFP is supported only on Windows")
}

func (controller *unsupportedController) Status() Status {
	if controller == nil {
		return Status{State: StatusDriverMissing}
	}
	return controller.status
}
