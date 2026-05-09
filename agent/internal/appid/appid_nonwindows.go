//go:build !windows

package appid

import "fmt"

func LookupTCPProcess(key FlowKey) (*ProcessIdentity, error) {
	return nil, fmt.Errorf("TCP process identity lookup is only supported on Windows: %+v", key)
}
