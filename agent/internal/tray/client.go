package tray

import "ztna.local/agent/internal/ipc"

var newDefaultClient = ipc.NewDefaultClient
var newDefaultBrowserOpener = func() func(string) error { return openBrowser }
