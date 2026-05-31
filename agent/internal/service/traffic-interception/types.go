package trafficinterception

import (
	"context"
	"net"
	"time"

	wfpcontrol "agent/internal/service/wfp-control"
)

const (
	DefaultProxyListenAddress = "127.0.0.1:18787"

	StatusDisabled = "disabled"
	StatusStarting = "starting"
	StatusReady    = "ready"
	StatusDegraded = "degraded"
	StatusStopped  = "stopped"
)

type Config struct {
	Enabled            bool
	ProxyListenAddress string
	WFPDevicePath      string
	FailClosed         bool
	ReadyTimeout       time.Duration
	StreamTimeout      time.Duration
}

type ResourceMapping struct {
	ResourceID  string
	FQDN        string
	Protocol    string
	Port        int
	SyntheticIP string
}

type Status struct {
	State              string
	ProxyListenAddress string
	ProxyLocalAddress  string
	RuleCount          int
	AcceptedCount      int64
	DeniedCount        int64
	LastError          string
	WFP                wfpcontrol.Status
}

type StreamRequest struct {
	ResourceID   string
	FQDN         string
	Protocol     string
	Port         int
	SyntheticIP  string
	ClientAddr   string
	OriginalAddr string
	Process      *ProcessIdentity
}

type StreamConnector interface {
	OpenResourceStream(context.Context, StreamRequest) (net.Conn, error)
}

type ProcessIdentity struct {
	PID    int
	Name   string
	Path   string
	SHA256 string
	Signer string
}
