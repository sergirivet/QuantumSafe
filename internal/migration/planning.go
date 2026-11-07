package migration

import (
	"fmt"
	"strings"

	"github.com/sergirivet/QuantumSafe/internal/inventory"
	"github.com/sergirivet/QuantumSafe/internal/pqc"
	"github.com/sergirivet/QuantumSafe/internal/risk"
)

const (
	SchemaVersion = 1
	PolicyVersion = "quantumsafe-migration-v1"
)

type Status string

const (
	StatusProposed Status = "proposed"
	StatusPlanned  Status = "planned"
	StatusBlocked  Status = "blocked"
	StatusActive   Status = "in_progress"
	StatusValidate Status = "validation"
	StatusComplete Status = "completed"
)

type PlanItem struct {
	ID                string             `json:"id"`
	ServiceID         int64              `json:"service_id"`
	AssetName         string             `json:"asset_name"`
	IP                string             `json:"ip"`
	Port              int                `json:"port"`
	Protocol          string             `json:"protocol"`
	CurrentAlgorithm  string             `json:"current_algorithm"`
	AlgorithmCategory string             `json:"algorithm_category"`
	Classification    pqc.Classification `json:"classification"`
	PQCReference      string             `json:"pqc_reference,omitempty"`
	RiskLevel         risk.Level         `json:"risk_level"`
	RiskScore         int                `json:"risk_score"`
	Priority          pqc.Priority       `json:"priority"`
	Status            Status             `json:"status"`
	Owner             string             `json:"owner,omitempty"`
	Deadline          string             `json:"deadline,omitempty"`
	Action            string             `json:"action"`
	Dependencies      []string           `json:"dependencies"`
	ValidationChecks  []string           `json:"validation_checks"`
	Reasons           []string           `json:"reasons"`
	Gaps              []string           `json:"gaps,omitempty"`
}

type Report struct {
	SchemaVersion int        `json:"schema_version"`
	PolicyVersion string     `json:"policy_version"`
	Catalog       string     `json:"catalog"`
	Target        string     `json:"target"`
	Items         []PlanItem `json:"items"`
	Gaps          []string   `json:"gaps,omitempty"`
}

func Build(snapshot inventory.Snapshot) Report {
	pqcReport := pqc.AssessSnapshot(snapshot)
	riskAssessments := risk.AssessSnapshot(snapshot)
	riskByObservation := make(map[string]risk.Assessment, len(riskAssessments))
	for _, assessment := range riskAssessments {
		key := fmt.Sprintf("%d:%s", assessment.ServiceID, assessment.Algorithm)
		riskByObservation[key] = assessment
	}

	report := Report{
		SchemaVersion: SchemaVersion,
		PolicyVersion: PolicyVersion,
		Catalog:       pqcReport.Catalog,
		Target:        snapshot.Target,
		Items:         make([]PlanItem, 0),
		Gaps:          append([]string(nil), pqcReport.Gaps...),
	}
	for _, service := range pqcReport.Services {
		for _, observation := range service.Observations {
			assessment := riskByObservation[fmt.Sprintf("%d:%s", service.ServiceID, observation.Algorithm)]
			item := PlanItem{
				ID:                planID(service.ServiceID, observation.Algorithm, observation.Category),
				ServiceID:         service.ServiceID,
				AssetName:         service.AssetName,
				IP:                service.IP,
				Port:              service.Port,
				Protocol:          service.Protocol,
				CurrentAlgorithm:  observation.Algorithm,
				AlgorithmCategory: observation.Category,
				Classification:    observation.Classification,
				PQCReference:      observation.Standard,
				RiskLevel:         assessment.Level,
				RiskScore:         assessment.Score,
				Priority:          observation.Priority,
				Status:            StatusProposed,
				Action:            actionFor(observation),
				Dependencies:      dependenciesFor(observation),
				ValidationChecks:  validationChecksFor(observation),
				Reasons:           append([]string(nil), observation.Reasons...),
				Gaps:              append([]string(nil), observation.Gaps...),
			}
			if assessment.Level == "" {
				item.Gaps = append(item.Gaps, "risk assessment unavailable")
			}
			report.Items = append(report.Items, item)
		}
	}
	if len(report.Items) == 0 {
		report.Gaps = append(report.Gaps, "no migration items could be generated from this snapshot")
	}
	return report
}

func planID(serviceID int64, algorithm, category string) string {
	value := strings.ToLower(strings.Join([]string{fmt.Sprint(serviceID), category, algorithm}, "-"))
	var builder strings.Builder
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
			builder.WriteRune(character)
		} else {
			builder.WriteRune('-')
		}
	}
	return "migration-" + builder.String()
}

func actionFor(observation pqc.ClassificationResult) string {
	switch observation.Classification {
	case pqc.QuantumVulnerable:
		return "identify owner and dependencies, select an approved post-quantum migration design, then validate the change"
	case pqc.PQCStandardized:
		return "validate deployment, interoperability and policy approval for the observed standardized PQC algorithm"
	case pqc.OngoingStandardization:
		return "track standardization status and avoid making this observation the sole basis for production migration"
	case pqc.ProtocolMetadata:
		return "collect public-key and key-exchange evidence before assigning a migration target"
	default:
		return "identify the cryptographic function and owner before selecting a migration action"
	}
}

func dependenciesFor(observation pqc.ClassificationResult) []string {
	dependencies := []string{"asset owner identification"}
	if observation.Classification == pqc.QuantumVulnerable || observation.Classification == pqc.ProtocolMetadata {
		dependencies = append(dependencies, "key exchange and certificate dependency inventory")
	}
	if observation.Function != "" {
		dependencies = append(dependencies, observation.Function+" compatibility assessment")
	}
	return dependencies
}

func validationChecksFor(observation pqc.ClassificationResult) []string {
	checks := []string{
		"repeat discovery after change",
		"confirm the previous observation is absent or intentionally retained",
		"record interoperability and rollback evidence",
	}
	if observation.Classification == pqc.QuantumVulnerable {
		checks = append(checks, "confirm no quantum-vulnerable public-key algorithm remains on the service")
	}
	return checks
}
