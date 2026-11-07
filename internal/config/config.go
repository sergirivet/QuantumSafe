package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	defaultLogLevel       = "info"
	defaultScanTimeout    = 5 * time.Second
	defaultMaxConcurrency = 8
	defaultMaxAddresses   = 32
	minScanTimeout        = 100 * time.Millisecond
	maxScanTimeout        = 5 * time.Minute
)

var ErrInvalidConfiguration = errors.New("invalid configuration")

type Config struct {
	LogLevel       string
	ScanTimeout    time.Duration
	MaxConcurrency int
	MaxAddresses   int
	DatabaseURL    string
	HTTPAddr       string
}

func Load() (Config, error) {
	config := Config{
		LogLevel:       valueOrDefault("QS_LOG_LEVEL", defaultLogLevel),
		ScanTimeout:    defaultScanTimeout,
		MaxConcurrency: defaultMaxConcurrency,
		MaxAddresses:   defaultMaxAddresses,
		DatabaseURL:    os.Getenv("QS_DATABASE_URL"),
		HTTPAddr:       valueOrDefault("QS_HTTP_ADDR", "127.0.0.1:8080"),
	}
	if config.LogLevel != "debug" && config.LogLevel != "info" && config.LogLevel != "warn" && config.LogLevel != "error" {
		return Config{}, fmt.Errorf("%w: QS_LOG_LEVEL must be debug, info, warn or error", ErrInvalidConfiguration)
	}
	if _, _, err := net.SplitHostPort(config.HTTPAddr); err != nil {
		return Config{}, fmt.Errorf("%w: QS_HTTP_ADDR must be host:port", ErrInvalidConfiguration)
	}

	if value := os.Getenv("QS_SCAN_TIMEOUT"); value != "" {
		timeout, err := time.ParseDuration(value)
		if err != nil || timeout < minScanTimeout || timeout > maxScanTimeout {
			return Config{}, fmt.Errorf("%w: QS_SCAN_TIMEOUT must be between %s and %s", ErrInvalidConfiguration, minScanTimeout, maxScanTimeout)
		}
		config.ScanTimeout = timeout
	}

	if value := os.Getenv("QS_SCAN_MAX_CONCURRENCY"); value != "" {
		maxConcurrency, err := positiveInt(value)
		if err != nil || maxConcurrency > 64 {
			return Config{}, fmt.Errorf("%w: QS_SCAN_MAX_CONCURRENCY must be between 1 and 64", ErrInvalidConfiguration)
		}
		config.MaxConcurrency = maxConcurrency
	}

	if value := os.Getenv("QS_SCAN_MAX_ADDRESSES"); value != "" {
		maxAddresses, err := positiveInt(value)
		if err != nil || maxAddresses > 256 {
			return Config{}, fmt.Errorf("%w: QS_SCAN_MAX_ADDRESSES must be between 1 and 256", ErrInvalidConfiguration)
		}
		config.MaxAddresses = maxAddresses
	}

	return config, nil
}

func valueOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func positiveInt(value string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return 0, fmt.Errorf("must be a positive integer: %q", value)
	}
	return parsed, nil
}
