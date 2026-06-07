package tray

import (
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

type guiWindowConfig struct {
	Title            string
	Width            int
	Height           int
	BackgroundColour options.RGBA
}

var defaultGUIWindowConfig = guiWindowConfig{
	Title:            "TRUSTAgent",
	Width:            680,
	Height:           560,
	BackgroundColour: options.RGBA{R: 242, G: 242, B: 240, A: 1},
}

func wailsAppOptions(app *GUIApp, config guiWindowConfig) *options.App {
	return &options.App{
		Title:         config.Title,
		Width:         config.Width,
		Height:        config.Height,
		DisableResize: true,
		Frameless:     true,
		AssetServer: &assetserver.Options{
			Assets: guiAssets,
		},
		BackgroundColour: &config.BackgroundColour,
		Windows: &windows.Options{
			Theme: windows.Light,
			CustomTheme: &windows.ThemeSettings{
				LightModeTitleBar:          windows.RGB(253, 246, 244),
				LightModeTitleBarInactive:  windows.RGB(253, 246, 244),
				LightModeTitleText:         windows.RGB(17, 17, 17),
				LightModeTitleTextInactive: windows.RGB(17, 17, 17),
				LightModeBorder:            windows.RGB(226, 218, 216),
				LightModeBorderInactive:    windows.RGB(226, 218, 216),
			},
		},
		OnStartup:  app.startup,
		OnShutdown: app.shutdown,
		Bind: []interface{}{
			app,
		},
	}
}
