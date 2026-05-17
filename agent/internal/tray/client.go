package tray

import "agent/internal/shared/ipc"

var newDefaultClient = ipc.NewDefaultClient
var newDefaultBrowserOpener = func() func(string) error { return openBrowser }
