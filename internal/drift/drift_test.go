package drift

import (
	"testing"

	"github.com/sergirivet/QuantumSafe/internal/inventory"
)

func TestCompareDetectsAlgorithmAndCertificateChanges(t *testing.T) {
	baseline := snapshot("example.com", "ECDSA", "cert-old")
	current := snapshot("example.com", "ML-DSA-65", "cert-new")

	report := Compare(baseline, current)
	if report.Status != StatusChanged || len(report.Events) != 3 {
		t.Fatalf("unexpected drift report: %+v", report)
	}
	foundRemoval := false
	for _, event := range report.Events {
		if event.Type == AlgorithmRemoved {
			foundRemoval = true
		}
	}
	if !foundRemoval {
		t.Fatalf("expected algorithm removal event: %+v", report.Events)
	}
}

func TestCompareDetectsServiceAddAndRemove(t *testing.T) {
	baseline := snapshot("example.com", "ECDSA", "cert-old")
	current := inventory.Snapshot{
		ID: 2, Target: "example.com",
		Asset: inventory.Asset{Name: "example.com", Services: []inventory.Service{{IP: "203.0.113.11", Port: 443, Protocol: "https"}}},
	}

	report := Compare(baseline, current)
	if report.Status != StatusChanged || len(report.Events) != 2 {
		t.Fatalf("unexpected service drift: %+v", report)
	}
}

func TestCompareIsInconclusiveForDifferentTargets(t *testing.T) {
	report := Compare(snapshot("one.example", "ECDSA", "cert-old"), snapshot("two.example", "ECDSA", "cert-old"))
	if report.Status != StatusInconclusive || len(report.Gaps) == 0 {
		t.Fatalf("expected inconclusive target mismatch: %+v", report)
	}
}

func TestCompareIsInconclusiveWithEmptySnapshot(t *testing.T) {
	report := Compare(snapshot("example.com", "ECDSA", "cert-old"), inventory.Snapshot{ID: 2, Target: "example.com"})
	if report.Status != StatusInconclusive || len(report.Gaps) == 0 {
		t.Fatalf("expected inconclusive empty snapshot: %+v", report)
	}
}

func snapshot(target, algorithm, fingerprint string) inventory.Snapshot {
	return inventory.Snapshot{ID: 1, Target: target, Asset: inventory.Asset{Name: target, Services: []inventory.Service{{ID: 1, IP: "203.0.113.10", Port: 443, Protocol: "https", Algorithms: []inventory.Algorithm{{Name: algorithm, Category: "public_key"}}, Certificates: []inventory.Certificate{{FingerprintSHA256: fingerprint}}}}}}
}
