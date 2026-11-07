package migration

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sergirivet/QuantumSafe/internal/inventory"
	"github.com/sergirivet/QuantumSafe/internal/pqc"
)

const ValidationSchemaVersion = 1

const (
	ValidationPassed       ValidationStatus = "passed"
	ValidationFailed       ValidationStatus = "failed"
	ValidationInconclusive ValidationStatus = "inconclusive"
)

type ValidationStatus string

type Check struct {
	Name     string           `json:"name"`
	Status   ValidationStatus `json:"status"`
	Details  string           `json:"details"`
	Evidence []string         `json:"evidence,omitempty"`
}

type ValidationReport struct {
	SchemaVersion       int              `json:"schema_version"`
	PolicyVersion       string           `json:"policy_version"`
	Target              string           `json:"target"`
	BaselineScanID      int64            `json:"baseline_scan_id"`
	CurrentScanID       int64            `json:"current_scan_id"`
	Status              ValidationStatus `json:"status"`
	Checks              []Check          `json:"checks"`
	RemovedAlgorithms   []string         `json:"removed_algorithms,omitempty"`
	RemainingAlgorithms []string         `json:"remaining_algorithms,omitempty"`
	CertificateChanges  []string         `json:"certificate_changes,omitempty"`
	Gaps                []string         `json:"gaps,omitempty"`
}

func Validate(baseline, current inventory.Snapshot) ValidationReport {
	report := ValidationReport{
		SchemaVersion:  ValidationSchemaVersion,
		PolicyVersion:  PolicyVersion,
		Target:         baseline.Target,
		BaselineScanID: baseline.ID,
		CurrentScanID:  current.ID,
		Status:         ValidationInconclusive,
		Checks:         make([]Check, 0),
		Gaps:           make([]string, 0),
	}

	if !sameTarget(baseline.Target, current.Target) {
		report.Checks = append(report.Checks, Check{
			Name:     "same_target",
			Status:   ValidationFailed,
			Details:  "baseline and current scans refer to different targets",
			Evidence: []string{baseline.Target, current.Target},
		})
		report.Status = ValidationFailed
		return report
	}
	report.Checks = append(report.Checks, Check{
		Name:     "same_target",
		Status:   ValidationPassed,
		Details:  "baseline and current scans refer to the same target",
		Evidence: []string{baseline.Target},
	})

	baselineServices := indexServices(baseline)
	currentServices := indexServices(current)
	baselineVulnerable := vulnerableAlgorithms(baselineServices)
	currentVulnerable := vulnerableAlgorithms(currentServices)

	for key, algorithm := range baselineVulnerable {
		if _, present := currentVulnerable[key]; present {
			report.RemainingAlgorithms = append(report.RemainingAlgorithms, algorithm)
		} else {
			report.RemovedAlgorithms = append(report.RemovedAlgorithms, algorithm)
		}
	}
	sort.Strings(report.RemovedAlgorithms)
	sort.Strings(report.RemainingAlgorithms)

	switch {
	case len(baselineVulnerable) == 0:
		report.Checks = append(report.Checks, Check{
			Name:    "vulnerable_algorithms",
			Status:  ValidationInconclusive,
			Details: "baseline contains no classified quantum-vulnerable public-key algorithm",
		})
		report.Gaps = append(report.Gaps, "no vulnerable baseline algorithm was available to validate")
	case len(currentVulnerable) == 0:
		report.Checks = append(report.Checks, Check{
			Name:     "vulnerable_algorithms",
			Status:   ValidationPassed,
			Details:  "all classified vulnerable baseline algorithms are absent from the current scan",
			Evidence: report.RemovedAlgorithms,
		})
	default:
		report.Checks = append(report.Checks, Check{
			Name:     "vulnerable_algorithms",
			Status:   ValidationFailed,
			Details:  "one or more classified vulnerable algorithms remain in the current scan",
			Evidence: report.RemainingAlgorithms,
		})
	}

	certificateChanges, certificateCheck := compareCertificates(baselineServices, currentServices)
	report.CertificateChanges = certificateChanges
	report.Checks = append(report.Checks, certificateCheck)

	serviceCheck := compareServiceCoverage(baselineServices, currentServices)
	report.Checks = append(report.Checks, serviceCheck)
	if serviceCheck.Status == ValidationInconclusive {
		report.Gaps = append(report.Gaps, serviceCheck.Details)
	}

	report.Status = overallStatus(report.Checks)
	return report
}

type serviceObservation struct {
	service    inventory.Service
	algorithms map[string]inventory.Algorithm
	certs      map[string]inventory.Certificate
}

func indexServices(snapshot inventory.Snapshot) map[string]serviceObservation {
	indexed := make(map[string]serviceObservation, len(snapshot.Asset.Services))
	for _, service := range snapshot.Asset.Services {
		algorithms := make(map[string]inventory.Algorithm, len(service.Algorithms))
		for _, algorithm := range service.Algorithms {
			algorithms[normalize(algorithm.Name)] = algorithm
		}
		certs := make(map[string]inventory.Certificate, len(service.Certificates))
		for _, certificate := range service.Certificates {
			certs[normalize(certificate.FingerprintSHA256)] = certificate
		}
		indexed[serviceKey(service)] = serviceObservation{service: service, algorithms: algorithms, certs: certs}
	}
	return indexed
}

func vulnerableAlgorithms(services map[string]serviceObservation) map[string]string {
	vulnerable := make(map[string]string)
	for serviceKey, observation := range services {
		for algorithmKey, algorithm := range observation.algorithms {
			classified := pqc.Classify(algorithm.Name, algorithm.Category)
			if classified.Classification == pqc.QuantumVulnerable {
				vulnerable[serviceKey+":"+algorithmKey] = algorithm.Name
			}
		}
	}
	return vulnerable
}

func compareCertificates(baseline, current map[string]serviceObservation) ([]string, Check) {
	changes := make([]string, 0)
	compared := 0
	for key, baselineService := range baseline {
		currentService, present := current[key]
		if !present || len(baselineService.certs) == 0 {
			continue
		}
		compared++
		for fingerprint := range baselineService.certs {
			if _, unchanged := currentService.certs[fingerprint]; !unchanged {
				changes = append(changes, key+":"+fingerprint)
			}
		}
	}
	sort.Strings(changes)
	if compared == 0 {
		return changes, Check{Name: "certificate_evidence", Status: ValidationInconclusive, Details: "no comparable baseline certificate evidence was available"}
	}
	if len(changes) == 0 {
		return changes, Check{Name: "certificate_evidence", Status: ValidationInconclusive, Details: "baseline certificates were observed but no certificate change was detected"}
	}
	return changes, Check{Name: "certificate_evidence", Status: ValidationPassed, Details: "certificate evidence changed for at least one comparable service", Evidence: changes}
}

func compareServiceCoverage(baseline, current map[string]serviceObservation) Check {
	missing := make([]string, 0)
	for key := range baseline {
		if _, present := current[key]; !present {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return Check{Name: "service_coverage", Status: ValidationInconclusive, Details: "baseline services are missing from the current scan", Evidence: missing}
	}
	return Check{Name: "service_coverage", Status: ValidationPassed, Details: "all baseline services are present in the current scan"}
}

func overallStatus(checks []Check) ValidationStatus {
	inconclusive := false
	for _, check := range checks {
		if check.Status == ValidationFailed {
			return ValidationFailed
		}
		if check.Status == ValidationInconclusive {
			inconclusive = true
		}
	}
	if inconclusive {
		return ValidationInconclusive
	}
	return ValidationPassed
}

func serviceKey(service inventory.Service) string {
	return fmt.Sprintf("%s:%d:%s", normalize(service.IP), service.Port, normalize(service.Protocol))
}

func sameTarget(left, right string) bool {
	return normalize(left) != "" && normalize(left) == normalize(right)
}

func normalize(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}
