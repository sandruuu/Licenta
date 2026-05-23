package wfpcontrol

import (
	"context"
	"net"
)

const (
	DefaultDevicePath = `\\.\TrustAgentWfp`

	StatusDisabled      = "disabled"
	StatusReady         = "ready"
	StatusDriverMissing = "driver_missing"
	StatusError         = "error"
)

type Config struct {
	Enabled    bool
	DevicePath string
}

type Rule struct {
	SyntheticIP string
	Port        int
	Protocol    string
}

type ApplyRequest struct {
	ProxyAddress string
	ProxyPort    int
	ProxyPID     uint32
	FailClosed   bool
	Rules        []Rule
}

type Destination struct {
	IP       string
	Port     int
	Protocol string
}

type Status struct {
	State      string
	DevicePath string
	RuleCount  int
	LastError  string
}

type Controller interface {
	ApplyRules(context.Context, ApplyRequest) error
	Clear(context.Context) error
	ResolveOriginalDestination(context.Context, net.Conn) (Destination, error)
	Status() Status
}
