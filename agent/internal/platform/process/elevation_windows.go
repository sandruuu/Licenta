//go:build windows

package process

import "golang.org/x/sys/windows"

func IsElevated() bool {
	token := windows.GetCurrentProcessToken()
	return token.IsElevated()
}
