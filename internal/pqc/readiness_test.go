package pqc

import (
	"testing"

	"github.com/sergirivet/QuantumSafe/internal/inventory"
)

func TestClassifyFinalizedNISTStandards(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		category  string
		standard  string
		function  string
	}{
		{"ML-KEM", "ML-KEM-768", "kem", "FIPS 203", "key_encapsulation"},
		{"ML-DSA", "ML-DSA-65", "signature", "FIPS 204", "digital_signature"},
		{"SLH-DSA", "SLH-DSA-SHA2-128s", "signature", "FIPS 205", "digital_signature"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := Classify(test.algorithm, test.category)
			if result.Classification != PQCStandardized || result.Standard != test.standard || result.Function != test.function {
				t.Fatalf("unexpected classification: %+v", result)
			}
			if result.Source.URL == "" || len(result.Reasons) == 0 {
				t.Fatalf("expected source and reason: %+v", result)
			}
		})
	}
}

func TestClassifyQuantumVulnerablePublicKey(t *testing.T) {
	result := Classify("ECDSA", "public_key")
	if result.Classification != QuantumVulnerable || result.QuantumRisk != RiskHigh || result.Priority != PriorityImmediate {
		t.Fatalf("unexpected vulnerable classification: %+v", result)
	}
	if len(result.Gaps) == 0 {
		t.Fatal("expected migration context gap")
	}
}

func TestClassifyOngoingStandardization(t *testing.T) {
	for _, algorithm := range []string{"Falcon-1024", "HQC-256"} {
		result := Classify(algorithm, "public_key")
		if result.Classification != OngoingStandardization || result.Priority != PriorityPlan {
			t.Fatalf("unexpected ongoing classification for %s: %+v", algorithm, result)
		}
	}
}

func TestClassifyProtocolMetadataDoesNotClaimPQCReadiness(t *testing.T) {
	result := Classify("TLS 1.3", "tls_version")
	if result.Classification != ProtocolMetadata || result.Priority != PriorityReview {
		t.Fatalf("unexpected protocol classification: %+v", result)
	}
	if len(result.Gaps) == 0 {
		t.Fatal("expected key exchange gap")
	}
}

func TestAssessSnapshotReportsGaps(t *testing.T) {
	report := AssessSnapshot(inventory.Snapshot{
		Target: "example.com",
		Asset: inventory.Asset{
			Name: "example.com",
			Services: []inventory.Service{{
				ID:       1,
				IP:       "203.0.113.10",
				Port:     443,
				Protocol: "https",
				Algorithms: []inventory.Algorithm{{
					Name: "ECDSA", Category: "public_key",
				}},
			}},
		},
	})
	if report.Catalog != CatalogVersion || len(report.Sources) != 4 || len(report.Services) != 1 {
		t.Fatalf("unexpected readiness report: %+v", report)
	}
	if report.Services[0].Observations[0].Classification != QuantumVulnerable {
		t.Fatalf("unexpected observation: %+v", report.Services[0].Observations[0])
	}
}
