package appid

import "net"

type ProcessIdentity struct {
	PID    uint32 `json:"pid,omitempty"`
	Name   string `json:"name,omitempty"`
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Signer string `json:"signer,omitempty"`
}

type FlowKey struct {
	LocalIP    net.IP
	LocalPort  uint16
	RemoteIP   net.IP
	RemotePort uint16
}
