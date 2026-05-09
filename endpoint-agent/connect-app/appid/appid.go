package appid

import "net"

// ProcessIdentity describes the local process that originated an intercepted
// TCP flow. The values are collected locally by connect-app and are treated by
// the policy engine as contextual risk signals, not as cryptographic proof.
type ProcessIdentity struct {
	PID    uint32 `json:"pid,omitempty"`
	Name   string `json:"name,omitempty"`
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Signer string `json:"signer,omitempty"`
}

// FlowKey identifies the TCP tuple observed on the TUN interface.
type FlowKey struct {
	LocalIP    net.IP
	LocalPort  uint16
	RemoteIP   net.IP
	RemotePort uint16
}
