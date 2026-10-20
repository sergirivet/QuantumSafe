package config

import "testing"

func TestLoadUsesDefaultLogLevel(t *testing.T) {
	t.Setenv("QS_LOG_LEVEL", "")

	config := Load()

	if config.LogLevel != "info" {
		t.Fatalf("expected default log level %q, got %q", "info", config.LogLevel)
	}
}

func TestLoadUsesConfiguredLogLevel(t *testing.T) {
	t.Setenv("QS_LOG_LEVEL", "debug")

	config := Load()

	if config.LogLevel != "debug" {
		t.Fatalf("expected configured log level %q, got %q", "debug", config.LogLevel)
	}
}
