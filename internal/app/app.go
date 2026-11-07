package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/sergirivet/QuantumSafe/internal/api"
	"github.com/sergirivet/QuantumSafe/internal/config"
	"github.com/sergirivet/QuantumSafe/internal/discovery"
	"github.com/sergirivet/QuantumSafe/internal/inventory"
	"github.com/sergirivet/QuantumSafe/internal/version"
)

var errInvalidCommand = errors.New("invalid command")

type scanStore interface {
	SaveReport(context.Context, discovery.Report) (inventory.ScanRecord, error)
	GetScan(context.Context, int64) (inventory.Snapshot, error)
	GetAsset(context.Context, int64) (inventory.Asset, error)
	ListAssets(context.Context, int, int) ([]inventory.Asset, int, error)
	ListServices(context.Context, int, int) ([]inventory.Service, int, error)
	ListCertificates(context.Context, int, int) ([]inventory.Certificate, int, error)
	ListAlgorithms(context.Context, int, int) ([]inventory.Algorithm, int, error)
}

type scanOutput struct {
	discovery.Report
	InventoryScanID *int64 `json:"inventory_scan_id,omitempty"`
}

func Run(ctx context.Context, args []string, output io.Writer, errorOutput io.Writer) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	scanner := discovery.NewWithOptions(discovery.Options{
		Timeout:        cfg.ScanTimeout,
		MaxConcurrency: cfg.MaxConcurrency,
		MaxAddresses:   cfg.MaxAddresses,
	})

	var store scanStore
	if cfg.DatabaseURL != "" {
		repository, err := inventory.NewPostgres(ctx, cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("connect inventory database: %w", err)
		}
		defer repository.Close()
		store = repository
	}
	return runWithConfig(ctx, args, output, errorOutput, scanner, store, cfg)
}

func runWithScanner(ctx context.Context, args []string, output io.Writer, errorOutput io.Writer, scanner discovery.Scanner) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("application canceled: %w", err)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	return runWithConfig(ctx, args, output, errorOutput, scanner, nil, cfg)
}

func runWithConfig(ctx context.Context, args []string, output io.Writer, errorOutput io.Writer, scanner discovery.Scanner, store scanStore, cfg config.Config) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("application canceled: %w", err)
	}

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
		return runScan(ctx, args[1:], output, scanner, store)
	case "serve":
		if len(args) != 1 {
			return fmt.Errorf("%w: serve does not accept arguments", errInvalidCommand)
		}
		return runServer(ctx, cfg, scanner, store)
	default:
		return fmt.Errorf("%w: unknown command %q", errInvalidCommand, args[0])
	}
}

func runServer(ctx context.Context, cfg config.Config, scanner discovery.Scanner, store scanStore) error {
	if store == nil {
		return fmt.Errorf("serve requires QS_DATABASE_URL")
	}

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           api.NewServer(scanner, store).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP API: %w", err)
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shutdown HTTP API: %w", err)
		}
		return nil
	}
}

func runScan(ctx context.Context, args []string, output io.Writer, scanner discovery.Scanner, store scanStore) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("scan canceled: %w", err)
	}
	if len(args) != 1 || args[0] == "" {
		return fmt.Errorf("%w: scan requires exactly one target", errInvalidCommand)
	}

	report, err := scanner.Scan(ctx, args[0])
	if err != nil {
		return fmt.Errorf("scan target %q: %w", args[0], err)
	}

	result := scanOutput{Report: report}
	if store != nil {
		record, err := store.SaveReport(ctx, report)
		if err != nil {
			return fmt.Errorf("persist scan: %w", err)
		}
		result.InventoryScanID = &record.ID
	}

	return json.NewEncoder(output).Encode(result)
}

func writeHelp(output io.Writer) error {
	_, err := io.WriteString(output, "Usage: quantumsafe <command> [arguments]\n\nCommands:\n  help                 Show this help\n  version              Show the application version\n  scan <target>        Discover DNS, TCP, HTTP and TLS details\n  serve                Start the REST API (requires PostgreSQL)\n")
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
