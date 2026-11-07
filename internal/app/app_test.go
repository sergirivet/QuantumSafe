package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sergirivet/QuantumSafe/internal/config"
	"github.com/sergirivet/QuantumSafe/internal/discovery"
	"github.com/sergirivet/QuantumSafe/internal/inventory"
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
	scanner := fakeScanner{report: discovery.Report{Target: "example.com"}}

	err := runWithScanner(context.Background(), []string{"scan", "example.com"}, &output, &errorOutput, scanner)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	var result discovery.Report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("expected valid JSON, got %v", err)
	}

	if result.Target != "example.com" {
		t.Fatalf("unexpected scan result: %+v", result)
	}
}

func TestRunScanPersistsReport(t *testing.T) {
	var output bytes.Buffer
	var errorOutput bytes.Buffer
	scanner := fakeScanner{report: discovery.Report{Target: "example.com"}}
	store := &fakeStore{record: inventory.ScanRecord{ID: 42}}

	err := runWithConfig(context.Background(), []string{"scan", "example.com"}, &output, &errorOutput, scanner, store, config.Config{LogLevel: "info"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	var result scanOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("expected valid JSON, got %v", err)
	}
	if result.InventoryScanID == nil || *result.InventoryScanID != 42 {
		t.Fatalf("expected persisted scan ID, got %+v", result.InventoryScanID)
	}
	if !store.saved {
		t.Fatal("expected report to be persisted")
	}
}

type fakeScanner struct {
	report discovery.Report
}

type fakeStore struct {
	record inventory.ScanRecord
	saved  bool
}

func (store *fakeStore) SaveReport(context.Context, discovery.Report) (inventory.ScanRecord, error) {
	store.saved = true
	return store.record, nil
}

func (store *fakeStore) GetScan(context.Context, int64) (inventory.Snapshot, error) {
	return inventory.Snapshot{}, nil
}

func (store *fakeStore) GetAsset(context.Context, int64) (inventory.Asset, error) {
	return inventory.Asset{}, nil
}

func (store *fakeStore) ListAssets(context.Context, int, int) ([]inventory.Asset, int, error) {
	return nil, 0, nil
}

func (store *fakeStore) ListServices(context.Context, int, int) ([]inventory.Service, int, error) {
	return nil, 0, nil
}

func (store *fakeStore) ListCertificates(context.Context, int, int) ([]inventory.Certificate, int, error) {
	return nil, 0, nil
}

func (store *fakeStore) ListAlgorithms(context.Context, int, int) ([]inventory.Algorithm, int, error) {
	return nil, 0, nil
}

func (scanner fakeScanner) Scan(context.Context, string) (discovery.Report, error) {
	return scanner.report, nil
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
