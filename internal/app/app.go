package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/sergirivet/QuantumSafe/internal/config"
	"github.com/sergirivet/QuantumSafe/internal/version"
)

var errInvalidCommand = errors.New("invalid command")

type scanResult struct {
	Command string `json:"command"`
	Target  string `json:"target"`
	Status  string `json:"status"`
}

func Run(ctx context.Context, args []string, output io.Writer, errorOutput io.Writer) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("application canceled: %w", err)
	}

	cfg := config.Load()

	var level slog.LevelVar
	level.Set(logLevel(cfg.LogLevel))

	logger := slog.New(slog.NewTextHandler(errorOutput, &slog.HandlerOptions{
		Level: &level,
	}))

	logger.DebugContext(ctx, "QuantumSafe started", "log_level", cfg.LogLevel)

	if len(args) == 0 {
		return writeHelp(output)
	}

	switch args[0] {
	case "help":
		if len(args) != 1 {
			return fmt.Errorf("%w: help does not accept arguments", errInvalidCommand)
		}
		return writeHelp(output)
	case "version":
		if len(args) != 1 {
			return fmt.Errorf("%w: version does not accept arguments", errInvalidCommand)
		}
		_, err := fmt.Fprintf(output, "quantumsafe %s\n", version.Version)
		return err
	case "scan":
		return runScan(ctx, args[1:], output)
	default:
		return fmt.Errorf("%w: unknown command %q", errInvalidCommand, args[0])
	}
}

func runScan(ctx context.Context, args []string, output io.Writer) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("scan canceled: %w", err)
	}
	if len(args) != 1 || args[0] == "" {
		return fmt.Errorf("%w: scan requires exactly one target", errInvalidCommand)
	}

	result := scanResult{
		Command: "scan",
		Target:  args[0],
		Status:  "not_implemented",
	}

	return json.NewEncoder(output).Encode(result)
}

func writeHelp(output io.Writer) error {
	_, err := io.WriteString(output, "Usage: quantumsafe <command> [arguments]\n\nCommands:\n  help                 Show this help\n  version              Show the application version\n  scan <target>        Scan a target (not implemented yet)\n")
	return err
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
