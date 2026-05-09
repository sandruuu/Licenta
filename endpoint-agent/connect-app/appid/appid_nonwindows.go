//go:build !windows

package appid

import "fmt"

// LookupTCPProcess is currently implemented for Windows, where connect-app
// runs with Wintun. Non-Windows builds keep the API available for tests and
// future ports, but return no process identity.
func LookupTCPProcess(key FlowKey) (*ProcessIdentity, error) {
	return nil, fmt.Errorf("process identity lookup is only implemented on Windows")
}
