//go:build !windows

package tun

import "fmt"

func Open(Config) (Device, error) {
	return nil, fmt.Errorf("TUN devices are only supported on Windows")
}
