package inventory

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sergirivet/QuantumSafe/internal/discovery"
)

func TestPostgresRepositoryIntegration(t *testing.T) {
	if os.Getenv("QS_RUN_POSTGRES_INTEGRATION") != "1" || os.Getenv("QS_DATABASE_URL") == "" {
		t.Skip("set QS_RUN_POSTGRES_INTEGRATION=1 and QS_DATABASE_URL to run PostgreSQL integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	repository, err := NewPostgres(ctx, os.Getenv("QS_DATABASE_URL"))
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	defer repository.Close()

	migration, err := os.ReadFile("../../migrations/001_initial_inventory.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := repository.pool.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}

	scannedAt := time.Now().UTC().Truncate(time.Microsecond)
	report := discovery.Report{
		SchemaVersion: 1,
		Target:        "inventory-integration.example",
		ScannedAt:     scannedAt,
		DurationMS:    123,
		Addresses:     []discovery.Address{{IP: "203.0.113.10"}},
		Services: []discovery.Service{{
			IP:       "203.0.113.10",
			Port:     443,
			Protocol: "https",
			TLS: &discovery.TLSObservation{
				FingerprintSHA256: strings.Repeat("a", 64),
				Version:           "TLS 1.3",
				CipherSuite:       "TLS_AES_128_GCM_SHA256",
				Subject:           "CN=inventory-integration.example",
				Issuer:            "CN=Example CA",
				DNSNames:          []string{"inventory-integration.example"},
				NotBefore:         scannedAt.Add(-time.Hour),
				NotAfter:          scannedAt.Add(time.Hour),
			},
		}},
	}

	record, err := repository.SaveReport(ctx, report)
	if err != nil {
		t.Fatalf("save report: %v", err)
	}
	t.Cleanup(func() {
		_, _ = repository.pool.Exec(context.Background(), "DELETE FROM scans WHERE id = $1", record.ID)
	})

	snapshot, err := repository.GetScan(ctx, record.ID)
	if err != nil {
		t.Fatalf("get report: %v", err)
	}
	if snapshot.Target != report.Target || snapshot.Asset.Name != report.Target {
		t.Fatalf("unexpected snapshot identity: %+v", snapshot)
	}
	if len(snapshot.Asset.Services) != 1 || len(snapshot.Asset.Services[0].Certificates) != 1 || len(snapshot.Asset.Services[0].Algorithms) != 2 {
		t.Fatalf("expected service, certificate and algorithms, got %+v", snapshot.Asset.Services)
	}
}
