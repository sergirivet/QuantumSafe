package config

import (
	"errors"
	"testing"
	"time"
)

func TestLoadUsesDefaultLogLevel(t *testing.T) {
	t.Setenv("QS_LOG_LEVEL", "")

	config, err := Load()
	if err != nil {
		t.Fatalf("expected valid default configuration, got %v", err)
	}

	if config.LogLevel != "info" {
		t.Fatalf("expected default log level %q, got %q", "info", config.LogLevel)
	}
}

func TestLoadUsesConfiguredLogLevel(t *testing.T) {
	t.Setenv("QS_LOG_LEVEL", "debug")

	config, err := Load()
	if err != nil {
		t.Fatalf("expected valid configured log level, got %v", err)
	}

	if config.LogLevel != "debug" {
		t.Fatalf("expected configured log level %q, got %q", "debug", config.LogLevel)
	}
}

func TestLoadParsesScanLimits(t *testing.T) {
	t.Setenv("QS_SCAN_TIMEOUT", "10s")
	t.Setenv("QS_SCAN_MAX_CONCURRENCY", "4")
	t.Setenv("QS_SCAN_MAX_ADDRESSES", "16")

	config, err := Load()
	if err != nil {
		t.Fatalf("expected valid scan configuration, got %v", err)
	}

	if config.ScanTimeout != 10*time.Second || config.MaxConcurrency != 4 || config.MaxAddresses != 16 {
		t.Fatalf("unexpected scan configuration: %+v", config)
	}
}

func TestLoadRejectsInvalidScanTimeout(t *testing.T) {
	t.Setenv("QS_SCAN_TIMEOUT", "1ns")

	_, err := Load()
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected invalid configuration error, got %v", err)
	}
}

func TestLoadRejectsInvalidLogLevel(t *testing.T) {
	t.Setenv("QS_LOG_LEVEL", "verbose")

	_, err := Load()
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected invalid configuration error, got %v", err)
	}
}

func TestLoadRejectsInvalidHTTPAddress(t *testing.T) {
	t.Setenv("QS_HTTP_ADDR", "localhost")

	_, err := Load()
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected invalid configuration error, got %v", err)
	}
}
