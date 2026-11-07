package pqc

import (
	"strings"

	"github.com/sergirivet/QuantumSafe/internal/inventory"
)

const (
	CatalogVersion = "nist-pqc-fips-203-205-v1"
	SchemaVersion  = 1

	FIPS203 = "https://csrc.nist.gov/pubs/fips/203/final"
	FIPS204 = "https://csrc.nist.gov/pubs/fips/204/final"
	FIPS205 = "https://csrc.nist.gov/pubs/fips/205/final"
	NISTPQC = "https://csrc.nist.gov/projects/post-quantum-cryptography"
)

type Classification string

const (
	Classical              Classification = "classical"
	QuantumVulnerable      Classification = "quantum_vulnerable"
	PQCStandardized        Classification = "pqc_standardized"
	OngoingStandardization Classification = "ongoing_standardization"
	ProtocolMetadata       Classification = "protocol_metadata"
	Unknown                Classification = "unknown"
)

type Priority string

const (
	PriorityImmediate Priority = "immediate"
	PriorityHigh      Priority = "high"
	PriorityPlan      Priority = "plan"
	PriorityReview    Priority = "review"
	PriorityMonitor   Priority = "monitor"
)

type QuantumRisk string

const (
	RiskHigh    QuantumRisk = "high"
	RiskReview  QuantumRisk = "review"
	RiskLow     QuantumRisk = "low"
	RiskUnknown QuantumRisk = "unknown"
)

type Source struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

type ClassificationResult struct {
	Algorithm      string         `json:"algorithm"`
	Category       string         `json:"category"`
	Classification Classification `json:"classification"`
	Function       string         `json:"function,omitempty"`
	Standard       string         `json:"standard,omitempty"`
	Source         Source         `json:"source"`
	QuantumRisk    QuantumRisk    `json:"quantum_risk"`
	Priority       Priority       `json:"priority"`
	Recommendation string         `json:"recommendation"`
	Reasons        []string       `json:"reasons"`
	Gaps           []string       `json:"gaps,omitempty"`
}

type ServiceReadiness struct {
	ServiceID    int64                  `json:"service_id"`
	AssetName    string                 `json:"asset_name"`
	IP           string                 `json:"ip"`
	Port         int                    `json:"port"`
	Protocol     string                 `json:"protocol"`
	Observations []ClassificationResult `json:"observations"`
}

type Report struct {
	SchemaVersion int                `json:"schema_version"`
	Catalog       string             `json:"catalog"`
	Sources       []Source           `json:"sources"`
	Target        string             `json:"target"`
	Services      []ServiceReadiness `json:"services"`
	Gaps          []string           `json:"gaps,omitempty"`
}

func Classify(algorithm, category string) ClassificationResult {
	result := ClassificationResult{
		Algorithm: algorithm,
		Category:  category,
		Source:    Source{ID: "NIST-PQC", Title: "NIST Post-Quantum Cryptography project", URL: NISTPQC},
		Reasons:   make([]string, 0),
		Gaps:      make([]string, 0),
	}
	name := strings.ToUpper(strings.TrimSpace(algorithm))

	switch {
	case strings.HasPrefix(name, "ML-KEM"):
		result.Classification = PQCStandardized
		result.Function = "key_encapsulation"
		result.Standard = "FIPS 203"
		result.Source = Source{ID: "FIPS-203", Title: "Module-Lattice-Based Key-Encapsulation Mechanism Standard", URL: FIPS203}
		result.QuantumRisk = RiskLow
		result.Priority = PriorityMonitor
		result.Recommendation = "track deployment and interoperability evidence; this catalog does not prove service configuration"
		result.Reasons = append(result.Reasons, "algorithm is covered by NIST FIPS 203")
	case strings.HasPrefix(name, "ML-DSA"):
		result.Classification = PQCStandardized
		result.Function = "digital_signature"
		result.Standard = "FIPS 204"
		result.Source = Source{ID: "FIPS-204", Title: "Module-Lattice-Based Digital Signature Standard", URL: FIPS204}
		result.QuantumRisk = RiskLow
		result.Priority = PriorityMonitor
		result.Recommendation = "track signing deployment and interoperability evidence; this catalog does not prove service configuration"
		result.Reasons = append(result.Reasons, "algorithm is covered by NIST FIPS 204")
	case strings.HasPrefix(name, "SLH-DSA"):
		result.Classification = PQCStandardized
		result.Function = "digital_signature"
		result.Standard = "FIPS 205"
		result.Source = Source{ID: "FIPS-205", Title: "Stateless Hash-Based Digital Signature Standard", URL: FIPS205}
		result.QuantumRisk = RiskLow
		result.Priority = PriorityMonitor
		result.Recommendation = "track signing deployment and interoperability evidence; this catalog does not prove service configuration"
		result.Reasons = append(result.Reasons, "algorithm is covered by NIST FIPS 205")
	case strings.Contains(name, "FALCON"), strings.Contains(name, "HQC"):
		result.Classification = OngoingStandardization
		result.QuantumRisk = RiskReview
		result.Priority = PriorityPlan
		result.Recommendation = "track the standardization status; do not treat this observation as a finalized FIPS deployment target"
		result.Reasons = append(result.Reasons, "NIST identifies this family in ongoing standardization work")
	case strings.Contains(name, "RSA"), strings.Contains(name, "ECDSA"), strings.Contains(name, "ECDH"), strings.Contains(name, "ED25519"), strings.Contains(name, "ED448"), strings.Contains(name, "DSA"):
		result.Classification = QuantumVulnerable
		result.Function = "public_key"
		result.QuantumRisk = RiskHigh
		result.Priority = PriorityImmediate
		result.Recommendation = "inventory dependencies and plan migration to an approved post-quantum design"
		result.Reasons = append(result.Reasons, "public-key algorithm is in the migration scope for post-quantum readiness")
		result.Gaps = append(result.Gaps, "deployment context and migration dependency graph are not yet modeled")
	case strings.HasPrefix(name, "TLS "), strings.Contains(name, "TLS_"):
		result.Classification = ProtocolMetadata
		result.QuantumRisk = RiskReview
		result.Priority = PriorityReview
		result.Recommendation = "inspect negotiated key exchange and certificate key algorithm before assigning PQC readiness"
		result.Reasons = append(result.Reasons, "protocol or cipher metadata alone does not identify the complete public-key migration surface")
		result.Gaps = append(result.Gaps, "key exchange and certificate context required")
	case strings.HasPrefix(name, "AES"), strings.HasPrefix(name, "CHACHA"), strings.HasPrefix(name, "SHA"):
		result.Classification = Classical
		result.QuantumRisk = RiskReview
		result.Priority = PriorityReview
		result.Recommendation = "assess key size, usage and policy separately; this catalog does not assign a symmetric security level"
		result.Reasons = append(result.Reasons, "classical symmetric or hash observation requires separate context")
	default:
		result.Classification = Unknown
		result.QuantumRisk = RiskUnknown
		result.Priority = PriorityReview
		result.Recommendation = "identify the algorithm and cryptographic function before making a migration decision"
		result.Reasons = append(result.Reasons, "algorithm is not recognized by the current catalog")
		result.Gaps = append(result.Gaps, "algorithm identity and function are unknown")
	}
	return result
}

func AssessSnapshot(snapshot inventory.Snapshot) Report {
	report := Report{
		SchemaVersion: SchemaVersion,
		Catalog:       CatalogVersion,
		Target:        snapshot.Target,
		Sources: []Source{
			{ID: "FIPS-203", Title: "Module-Lattice-Based Key-Encapsulation Mechanism Standard", URL: FIPS203},
			{ID: "FIPS-204", Title: "Module-Lattice-Based Digital Signature Standard", URL: FIPS204},
			{ID: "FIPS-205", Title: "Stateless Hash-Based Digital Signature Standard", URL: FIPS205},
			{ID: "NIST-PQC", Title: "NIST Post-Quantum Cryptography project", URL: NISTPQC},
		},
		Services: make([]ServiceReadiness, 0),
	}
	for _, service := range snapshot.Asset.Services {
		readiness := ServiceReadiness{
			ServiceID:    service.ID,
			AssetName:    snapshot.Asset.Name,
			IP:           service.IP,
			Port:         service.Port,
			Protocol:     service.Protocol,
			Observations: make([]ClassificationResult, 0, len(service.Algorithms)),
		}
		for _, algorithm := range service.Algorithms {
			readiness.Observations = append(readiness.Observations, Classify(algorithm.Name, algorithm.Category))
		}
		if len(readiness.Observations) == 0 {
			report.Gaps = append(report.Gaps, "service "+service.IP+" has no cryptographic algorithm observations")
		}
		report.Services = append(report.Services, readiness)
	}
	if len(report.Services) == 0 {
		report.Gaps = append(report.Gaps, "scan contains no services to assess")
	}
	return report
}
