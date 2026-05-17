package dataplane

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

type Relay struct {
	DialTimeout time.Duration
}

func NewRelay(dialTimeout time.Duration) *Relay {
	return &Relay{DialTimeout: dialTimeout}
}

func (relay *Relay) Connect(host string, port int) (net.Conn, error) {
	if host == "" {
		return nil, fmt.Errorf("target host is required")
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("target port %d is outside the valid TCP range", port)
	}
	timeout := relay.DialTimeout
	if timeout <= 0 {
		return nil, fmt.Errorf("relay dial timeout must be configured")
	}
	return net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
}
