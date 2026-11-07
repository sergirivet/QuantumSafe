package risk

import (
	"errors"
	"testing"

	"github.com/sergirivet/QuantumSafe/internal/inventory"
)

func TestAssessQuantumVulnerablePublicKey(t *testing.T) {
	assessment, err := Assess(Input{
		ServiceID:           10,
		AssetName:           "payments-api",
		Algorithm:           "ECDSA P-256",
		AlgorithmCategory:   "public_key",
		InternetExposed:     true,
		BusinessCriticality: 5,
		DataSensitivity:     5,
		DependencyImpact:    4,
		MigrationComplexity: 4,
		CryptoAgility:       1,
	})
	if err != nil {
		t.Fatalf("expected valid assessment, got %v", err)
	}
	if assessment.Level != LevelCritical {
		t.Fatalf("expected critical risk, got %s (%d/%d)", assessment.Level, assessment.Score, assessment.MaxScore)
	}
	if len(assessment.Reasons) == 0 || len(assessment.MissingContext) != 0 {
		t.Fatalf("expected reasons and complete context, got %+v", assessment)
	}
}

func TestAssessUnknownContextIsExplicit(t *testing.T) {
	assessment, err := Assess(Input{
		AssetName:         "legacy-service",
		Algorithm:         "TLS 1.3",
		AlgorithmCategory: "tls_version",
		InternetExposed:   false,
	})
	if err != nil {
		t.Fatalf("expected valid assessment, got %v", err)
	}
	if assessment.Level != LevelMedium {
		t.Fatalf("expected medium risk with unknown context, got %s", assessment.Level)
	}
	if len(assessment.MissingContext) != 5 {
		t.Fatalf("expected five missing context fields, got %v", assessment.MissingContext)
	}
	if len(assessment.Reasons) == 0 {
		t.Fatal("expected explainable reasons")
	}
}

func TestAssessRejectsOutOfRangeContext(t *testing.T) {
	_, err := Assess(Input{Algorithm: "TLS 1.3", DataSensitivity: 6})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid input error, got %v", err)
	}
}

func TestAssessRejectsMissingAlgorithm(t *testing.T) {
	_, err := Assess(Input{})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid input error, got %v", err)
	}
}

func TestAssessSnapshotCreatesOneAssessmentPerAlgorithm(t *testing.T) {
	assessments := AssessSnapshot(inventory.Snapshot{
		Asset: inventory.Asset{
			Name: "example.com",
			Services: []inventory.Service{{
				ID:       1,
				IP:       "203.0.113.10",
				Port:     443,
				Protocol: "https",
				Algorithms: []inventory.Algorithm{
					{Name: "TLS 1.3", Category: "tls_version"},
					{Name: "TLS_AES_128_GCM_SHA256", Category: "cipher_suite"},
				},
			}},
		},
	})
	if len(assessments) != 2 {
		t.Fatalf("expected two assessments, got %d", len(assessments))
	}
	if assessments[0].PolicyVersion != PolicyVersion || assessments[0].SchemaVersion != SchemaVersion {
		t.Fatalf("unexpected policy metadata: %+v", assessments[0])
	}
}
