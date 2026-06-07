//go:build windows

package tray

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	flashWindowTray      = 0x00000002
	flashWindowTimerNoFG = 0x0000000c
)

var (
	user32DLL         = windows.NewLazySystemDLL("user32.dll")
	findWindowProc    = user32DLL.NewProc("FindWindowW")
	flashWindowExProc = user32DLL.NewProc("FlashWindowEx")
)

type flashWindowInfo struct {
	Size    uint32
	HWND    windows.Handle
	Flags   uint32
	Count   uint32
	Timeout uint32
}

func (app *GUIApp) FlashWindowAttention() {
	title, err := windows.UTF16PtrFromString(defaultGUIWindowConfig.Title)
	if err != nil {
		return
	}
	hwnd, _, _ := findWindowProc.Call(0, uintptr(unsafe.Pointer(title)))
	if hwnd == 0 {
		return
	}
	info := flashWindowInfo{
		Size:  uint32(unsafe.Sizeof(flashWindowInfo{})),
		HWND:  windows.Handle(hwnd),
		Flags: flashWindowTray | flashWindowTimerNoFG,
		Count: 4,
	}
	flashWindowExProc.Call(uintptr(unsafe.Pointer(&info)))
}
