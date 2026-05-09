package relay

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

type Relay struct {
	DialTimeout time.Duration
}

func New() *Relay {
	return &Relay{DialTimeout: 10 * time.Second}
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
		timeout = 10 * time.Second
	}
	return net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
}
