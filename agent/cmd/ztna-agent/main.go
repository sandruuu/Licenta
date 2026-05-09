package main

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"ztna.local/agent/internal/app"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
	if err := app.Run(context.Background(), os.Args[1:], logger); err != nil {
		if errors.Is(err, app.ErrUsage) {
			app.PrintUsage(os.Stderr)
			os.Exit(2)
		}
		logger.Error("ZTNA Agent exited with error", "error", err)
		os.Exit(1)
	}
}
