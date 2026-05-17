package tray

import (
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

type guiWindowConfig struct {
	Title            string
	Width            int
	Height           int
	MinWidth         int
	MinHeight        int
	BackgroundColour options.RGBA
}

var defaultGUIWindowConfig = guiWindowConfig{
	Title:            "TustAGENT",
	Width:            1080,
	Height:           760,
	MinWidth:         920,
	MinHeight:        620,
	BackgroundColour: options.RGBA{R: 245, G: 247, B: 250, A: 1},
}

func wailsAppOptions(app *GUIApp, config guiWindowConfig) *options.App {
	return &options.App{
		Title:     config.Title,
		Width:     config.Width,
		Height:    config.Height,
		MinWidth:  config.MinWidth,
		MinHeight: config.MinHeight,
		AssetServer: &assetserver.Options{
			Assets: guiAssets,
		},
		BackgroundColour: &config.BackgroundColour,
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind: []interface{}{
			app,
		},
	}
}
