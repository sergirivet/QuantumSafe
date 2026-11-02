package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var output bytes.Buffer
	var errorOutput bytes.Buffer

	err := Run(context.Background(), []string{"version"}, &output, &errorOutput)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !strings.Contains(output.String(), "quantumsafe 0.1.0-develop") {
		t.Fatalf("unexpected version output: %q", output.String())
	}
}

func TestRunScanReturnsJSON(t *testing.T) {
	var output bytes.Buffer
	var errorOutput bytes.Buffer

	err := Run(context.Background(), []string{"scan", "example.com"}, &output, &errorOutput)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	var result scanResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("expected valid JSON, got %v", err)
	}

	if result.Target != "example.com" || result.Status != "not_implemented" {
		t.Fatalf("unexpected scan result: %+v", result)
	}
}

func TestRunScanRequiresTarget(t *testing.T) {
	var output bytes.Buffer
	var errorOutput bytes.Buffer

	err := Run(context.Background(), []string{"scan"}, &output, &errorOutput)
	if !errors.Is(err, errInvalidCommand) {
		t.Fatalf("expected invalid command error, got %v", err)
	}
}

func TestRunHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var output bytes.Buffer
	var errorOutput bytes.Buffer

	err := Run(ctx, []string{"help"}, &output, &errorOutput)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
}
