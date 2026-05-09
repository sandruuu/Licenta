//go:build !windows

package process

import "os"

func IsElevated() bool {
	return os.Geteuid() == 0
}
