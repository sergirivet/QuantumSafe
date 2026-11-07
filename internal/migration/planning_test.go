package migration

import (
	"testing"

	"github.com/sergirivet/QuantumSafe/internal/inventory"
	"github.com/sergirivet/QuantumSafe/internal/pqc"
	"github.com/sergirivet/QuantumSafe/internal/risk"
)

func TestBuildCreatesActionablePlanForVulnerableAlgorithm(t *testing.T) {
	report := Build(inventory.Snapshot{
		Target: "payments-api",
		Asset: inventory.Asset{
			Name: "payments-api",
			Services: []inventory.Service{{
				ID:       10,
				IP:       "203.0.113.10",
				Port:     443,
				Protocol: "https",
				Algorithms: []inventory.Algorithm{{
					Name: "ECDSA", Category: "public_key",
				}},
			}},
		},
	})

	if report.PolicyVersion != PolicyVersion || len(report.Items) != 1 {
		t.Fatalf("unexpected plan: %+v", report)
	}
	item := report.Items[0]
	if item.Classification != pqc.QuantumVulnerable || item.Priority != pqc.PriorityImmediate || item.RiskLevel != risk.LevelHigh {
		t.Fatalf("unexpected vulnerable plan item: %+v", item)
	}
	if item.Status != StatusProposed || item.Owner != "" || item.Deadline != "" {
		t.Fatalf("expected proposed unassigned item: %+v", item)
	}
	if len(item.Dependencies) == 0 || len(item.ValidationChecks) == 0 {
		t.Fatalf("expected dependencies and validation checks: %+v", item)
	}
}

func TestBuildDoesNotTreatTLSMetadataAsMigrationCompletion(t *testing.T) {
	report := Build(inventory.Snapshot{
		Target: "example.com",
		Asset: inventory.Asset{
			Name: "example.com",
			Services: []inventory.Service{{
				ID:       1,
				IP:       "203.0.113.20",
				Port:     443,
				Protocol: "https",
				Algorithms: []inventory.Algorithm{{
					Name: "TLS 1.3", Category: "tls_version",
				}},
			}},
		},
	})

	item := report.Items[0]
	if item.Classification != pqc.ProtocolMetadata || item.Priority != pqc.PriorityReview {
		t.Fatalf("unexpected protocol plan item: %+v", item)
	}
	if item.Status == StatusComplete || len(item.Gaps) == 0 {
		t.Fatalf("expected incomplete plan with gaps: %+v", item)
	}
}

func TestBuildReportsEmptySnapshotGap(t *testing.T) {
	report := Build(inventory.Snapshot{Target: "empty.example"})
	if len(report.Items) != 0 || len(report.Gaps) == 0 {
		t.Fatalf("expected gap for empty snapshot: %+v", report)
	}
}
