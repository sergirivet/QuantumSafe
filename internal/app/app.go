package app

import (
	"context"
	"log/slog"
	"os"

	"github.com/sergirivet/QuantumSafe/internal/config"
)

func Run(ctx context.Context) error {
	cfg := config.Load()

	var level slog.LevelVar
	level.Set(logLevel(cfg.LogLevel))

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: &level,
	}))

	logger.InfoContext(ctx, "QuantumSafe started", "log_level", cfg.LogLevel)

	return nil
}

func logLevel(value string) slog.Level {
	switch value {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
