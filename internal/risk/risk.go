package risk

import (
	"errors"
	"fmt"
	"strings"

	"github.com/sergirivet/QuantumSafe/internal/inventory"
)

const (
	PolicyVersion = "quantumsafe-risk-v1"
	SchemaVersion = 1
)

var ErrInvalidInput = errors.New("invalid risk input")

type Level string

const (
	LevelLow      Level = "LOW"
	LevelMedium   Level = "MEDIUM"
	LevelHigh     Level = "HIGH"
	LevelCritical Level = "CRITICAL"
)

type Input struct {
	ServiceID           int64
	AssetName           string
	IP                  string
	Port                int
	Protocol            string
	Algorithm           string
	AlgorithmCategory   string
	InternetExposed     bool
	BusinessCriticality int
	DataSensitivity     int
	DependencyImpact    int
	MigrationComplexity int
	CryptoAgility       int
}

type Factor struct {
	Name      string `json:"name"`
	Score     int    `json:"score"`
	MaxScore  int    `json:"max_score"`
	Rationale string `json:"rationale"`
	Evidence  string `json:"evidence"`
}

type Assessment struct {
	SchemaVersion  int      `json:"schema_version"`
	PolicyVersion  string   `json:"policy_version"`
	ServiceID      int64    `json:"service_id"`
	AssetName      string   `json:"asset_name"`
	Algorithm      string   `json:"algorithm"`
	Score          int      `json:"score"`
	MaxScore       int      `json:"max_score"`
	Level          Level    `json:"level"`
	Factors        []Factor `json:"factors"`
	Reasons        []string `json:"reasons"`
	MissingContext []string `json:"missing_context,omitempty"`
}

func Assess(input Input) (Assessment, error) {
	if err := validate(input); err != nil {
		return Assessment{}, err
	}

	factors := []Factor{
		algorithmFactor(input.Algorithm, input.AlgorithmCategory),
		internetExposureFactor(input.InternetExposed),
		contextFactor("business_criticality", input.BusinessCriticality, "business criticality supplied by the organization"),
		contextFactor("data_sensitivity", input.DataSensitivity, "data sensitivity supplied by the organization"),
		contextFactor("dependency_impact", input.DependencyImpact, "dependency impact supplied by the organization"),
		contextFactor("migration_complexity", input.MigrationComplexity, "migration complexity estimated by the organization"),
		cryptoAgilityFactor(input.CryptoAgility),
	}

	assessment := Assessment{
		SchemaVersion:  SchemaVersion,
		PolicyVersion:  PolicyVersion,
		ServiceID:      input.ServiceID,
		AssetName:      input.AssetName,
		Algorithm:      input.Algorithm,
		MaxScore:       len(factors) * 5,
		Factors:        factors,
		Reasons:        make([]string, 0),
		MissingContext: missingContext(input),
	}
	for _, factor := range factors {
		assessment.Score += factor.Score
		if factor.Score >= 4 {
			assessment.Reasons = append(assessment.Reasons, factor.Rationale)
		}
	}
	for _, missing := range assessment.MissingContext {
		assessment.Reasons = append(assessment.Reasons, "missing context: "+missing)
	}
	assessment.Level = levelForScore(assessment.Score)
	return assessment, nil
}

func AssessSnapshot(snapshot inventory.Snapshot) []Assessment {
	assessments := make([]Assessment, 0)
	for _, service := range snapshot.Asset.Services {
		for _, algorithm := range service.Algorithms {
			assessment, err := Assess(Input{
				ServiceID:         service.ID,
				AssetName:         snapshot.Asset.Name,
				IP:                service.IP,
				Port:              service.Port,
				Protocol:          service.Protocol,
				Algorithm:         algorithm.Name,
				AlgorithmCategory: algorithm.Category,
				InternetExposed:   true,
			})
			if err == nil {
				assessments = append(assessments, assessment)
			}
		}
	}
	return assessments
}

func validate(input Input) error {
	if strings.TrimSpace(input.Algorithm) == "" {
		return fmt.Errorf("%w: algorithm is required", ErrInvalidInput)
	}
	for name, value := range map[string]int{
		"business_criticality": input.BusinessCriticality,
		"data_sensitivity":     input.DataSensitivity,
		"dependency_impact":    input.DependencyImpact,
		"migration_complexity": input.MigrationComplexity,
		"crypto_agility":       input.CryptoAgility,
	} {
		if value < 0 || value > 5 {
			return fmt.Errorf("%w: %s must be between 0 and 5", ErrInvalidInput, name)
		}
	}
	return nil
}

func algorithmFactor(algorithm, category string) Factor {
	name := strings.ToUpper(algorithm)
	category = strings.ToLower(category)
	switch {
	case strings.Contains(name, "RSA"), strings.Contains(name, "ECDSA"), strings.Contains(name, "ECDH"), strings.Contains(name, "ED25519"), strings.Contains(name, "ED448"), strings.Contains(name, "DSA"):
		return Factor{"algorithm_risk", 5, 5, "quantum-vulnerable public-key algorithm observed", algorithm + " / " + category}
	case strings.Contains(name, "TLS 1.0"), strings.Contains(name, "TLS 1.1"), strings.Contains(name, "3DES"), strings.Contains(name, "RC4"), strings.Contains(name, "EXPORT"), strings.Contains(name, "NULL"):
		return Factor{"algorithm_risk", 5, 5, "legacy or prohibited cryptographic construction observed", algorithm + " / " + category}
	case strings.Contains(name, "TLS 1.2"):
		return Factor{"algorithm_risk", 2, 5, "classical protocol version requires contextual review", algorithm + " / " + category}
	case strings.Contains(name, "TLS 1.3"):
		return Factor{"algorithm_risk", 1, 5, "modern protocol version observed; algorithm inventory is still incomplete", algorithm + " / " + category}
	default:
		return Factor{"algorithm_risk", 3, 5, "algorithm classification is unknown and requires review", algorithm + " / " + category}
	}
}

func internetExposureFactor(exposed bool) Factor {
	if exposed {
		return Factor{"internet_exposure", 5, 5, "internet exposed", "public-target discovery mode"}
	}
	return Factor{"internet_exposure", 0, 5, "not marked as internet exposed", "input context"}
}

func contextFactor(name string, value int, evidence string) Factor {
	if value == 0 {
		return Factor{name, 3, 5, name + " is unknown; neutral score applied", "missing organization context"}
	}
	return Factor{name, value, 5, name + " supplied by organization", evidence}
}

func cryptoAgilityFactor(value int) Factor {
	if value == 0 {
		return Factor{"crypto_agility", 3, 5, "crypto agility is unknown; neutral score applied", "missing organization context"}
	}
	return Factor{"crypto_agility", 5 - value, 5, "lower crypto agility increases migration risk", fmt.Sprintf("agility score=%d/5", value)}
}

func missingContext(input Input) []string {
	missing := make([]string, 0, 5)
	if input.BusinessCriticality == 0 {
		missing = append(missing, "business_criticality")
	}
	if input.DataSensitivity == 0 {
		missing = append(missing, "data_sensitivity")
	}
	if input.DependencyImpact == 0 {
		missing = append(missing, "dependency_impact")
	}
	if input.MigrationComplexity == 0 {
		missing = append(missing, "migration_complexity")
	}
	if input.CryptoAgility == 0 {
		missing = append(missing, "crypto_agility")
	}
	return missing
}

func levelForScore(score int) Level {
	switch {
	case score >= 28:
		return LevelCritical
	case score >= 20:
		return LevelHigh
	case score >= 10:
		return LevelMedium
	default:
		return LevelLow
	}
}
