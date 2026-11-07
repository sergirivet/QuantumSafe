package migration

import (
	"testing"

	"github.com/sergirivet/QuantumSafe/internal/inventory"
)

func TestValidatePassesWhenVulnerableAlgorithmIsRemoved(t *testing.T) {
	baseline := snapshotWithService("payments-api", "ECDSA", "certificate-old")
	current := snapshotWithService("payments-api", "ML-DSA-65", "certificate-new")

	report := Validate(baseline, current)
	if report.Status != ValidationPassed {
		t.Fatalf("expected passed validation, got %+v", report)
	}
	if len(report.RemovedAlgorithms) != 1 || len(report.CertificateChanges) != 1 {
		t.Fatalf("expected removed algorithm and certificate change: %+v", report)
	}
}

func TestValidateFailsWhenVulnerableAlgorithmRemains(t *testing.T) {
	baseline := snapshotWithService("payments-api", "ECDSA", "certificate-old")
	current := snapshotWithService("payments-api", "ECDSA", "certificate-new")

	report := Validate(baseline, current)
	if report.Status != ValidationFailed {
		t.Fatalf("expected failed validation, got %+v", report)
	}
	if len(report.RemainingAlgorithms) != 1 {
		t.Fatalf("expected remaining algorithm: %+v", report)
	}
}

func TestValidateIsInconclusiveWithoutBaselineVulnerableAlgorithm(t *testing.T) {
	baseline := snapshotWithService("example.com", "TLS 1.3", "certificate-old")
	current := snapshotWithService("example.com", "TLS 1.3", "certificate-old")

	report := Validate(baseline, current)
	if report.Status != ValidationInconclusive {
		t.Fatalf("expected inconclusive validation, got %+v", report)
	}
}

func TestValidateFailsForDifferentTargets(t *testing.T) {
	baseline := snapshotWithService("payments-api", "ECDSA", "certificate-old")
	current := snapshotWithService("other-api", "ML-DSA-65", "certificate-new")

	report := Validate(baseline, current)
	if report.Status != ValidationFailed || report.Checks[0].Name != "same_target" {
		t.Fatalf("expected target failure, got %+v", report)
	}
}

func TestValidateIsInconclusiveWhenServiceDisappears(t *testing.T) {
	baseline := snapshotWithService("payments-api", "ECDSA", "certificate-old")
	current := inventory.Snapshot{ID: 2, Target: "payments-api"}

	report := Validate(baseline, current)
	if report.Status != ValidationInconclusive {
		t.Fatalf("missing service evidence should be inconclusive, got %+v", report)
	}
	foundCoverage := false
	for _, check := range report.Checks {
		if check.Name == "service_coverage" && check.Status == ValidationInconclusive {
			foundCoverage = true
		}
	}
	if !foundCoverage {
		t.Fatalf("expected inconclusive service coverage check: %+v", report)
	}
}

func snapshotWithService(target, algorithm, fingerprint string) inventory.Snapshot {
	return inventory.Snapshot{
		ID:     1,
		Target: target,
		Asset: inventory.Asset{
			Name: target,
			Services: []inventory.Service{{
				ID:       10,
				IP:       "203.0.113.10",
				Port:     443,
				Protocol: "https",
				Certificates: []inventory.Certificate{{
					FingerprintSHA256: fingerprint,
				}},
				Algorithms: []inventory.Algorithm{{
					Name:     algorithm,
					Category: "public_key",
				}},
			}},
		},
	}
}
