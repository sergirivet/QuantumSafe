package drift

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sergirivet/QuantumSafe/internal/inventory"
)

const SchemaVersion = 1

type Status string

const (
	StatusChanged      Status = "changed"
	StatusUnchanged    Status = "unchanged"
	StatusInconclusive Status = "inconclusive"
)

type EventType string

const (
	ServiceAdded       EventType = "service_added"
	ServiceRemoved     EventType = "service_removed"
	AlgorithmAdded     EventType = "algorithm_added"
	AlgorithmRemoved   EventType = "algorithm_removed"
	CertificateChanged EventType = "certificate_changed"
)

type Event struct {
	Type      EventType `json:"type"`
	ServiceID int64     `json:"service_id"`
	Service   string    `json:"service"`
	Details   string    `json:"details"`
	Evidence  []string  `json:"evidence,omitempty"`
}

type Report struct {
	SchemaVersion  int      `json:"schema_version"`
	Target         string   `json:"target"`
	BaselineScanID int64    `json:"baseline_scan_id"`
	CurrentScanID  int64    `json:"current_scan_id"`
	Status         Status   `json:"status"`
	Events         []Event  `json:"events"`
	Gaps           []string `json:"gaps,omitempty"`
}

func Compare(baseline, current inventory.Snapshot) Report {
	report := Report{
		SchemaVersion:  SchemaVersion,
		Target:         baseline.Target,
		BaselineScanID: baseline.ID,
		CurrentScanID:  current.ID,
		Status:         StatusUnchanged,
		Events:         make([]Event, 0),
		Gaps:           make([]string, 0),
	}
	if normalize(baseline.Target) == "" || normalize(baseline.Target) != normalize(current.Target) {
		report.Status = StatusInconclusive
		report.Gaps = append(report.Gaps, "baseline and current scans do not identify the same target")
		return report
	}

	baselineServices := index(baseline)
	currentServices := index(current)
	for key, before := range baselineServices {
		after, exists := currentServices[key]
		if !exists {
			report.Events = append(report.Events, Event{Type: ServiceRemoved, ServiceID: before.service.ID, Service: key, Details: "service disappeared from current scan"})
			continue
		}
		for algorithm := range before.algorithms {
			if _, present := after.algorithms[algorithm]; !present {
				report.Events = append(report.Events, Event{Type: AlgorithmRemoved, ServiceID: before.service.ID, Service: key, Details: "algorithm disappeared from current scan", Evidence: []string{algorithm}})
			}
		}
		for algorithm := range after.algorithms {
			if _, present := before.algorithms[algorithm]; !present {
				report.Events = append(report.Events, Event{Type: AlgorithmAdded, ServiceID: after.service.ID, Service: key, Details: "algorithm appeared in current scan", Evidence: []string{algorithm}})
			}
		}
		if !sameCertificates(before.certificates, after.certificates) {
			report.Events = append(report.Events, Event{Type: CertificateChanged, ServiceID: after.service.ID, Service: key, Details: "certificate fingerprint set changed"})
		}
	}
	for key, after := range currentServices {
		if _, exists := baselineServices[key]; !exists {
			report.Events = append(report.Events, Event{Type: ServiceAdded, ServiceID: after.service.ID, Service: key, Details: "service appeared in current scan"})
		}
	}
	sort.Slice(report.Events, func(left, right int) bool {
		if report.Events[left].Service == report.Events[right].Service {
			return report.Events[left].Type < report.Events[right].Type
		}
		return report.Events[left].Service < report.Events[right].Service
	})
	if len(report.Events) > 0 {
		report.Status = StatusChanged
	}
	if len(baselineServices) == 0 || len(currentServices) == 0 {
		report.Status = StatusInconclusive
		report.Gaps = append(report.Gaps, "one snapshot contains no services; drift confidence is limited")
	}
	return report
}

type observation struct {
	service      inventory.Service
	algorithms   map[string]struct{}
	certificates map[string]struct{}
}

func index(snapshot inventory.Snapshot) map[string]observation {
	result := make(map[string]observation, len(snapshot.Asset.Services))
	for _, service := range snapshot.Asset.Services {
		algorithms := make(map[string]struct{})
		for _, algorithm := range service.Algorithms {
			algorithms[normalize(algorithm.Category+":"+algorithm.Name)] = struct{}{}
		}
		certificates := make(map[string]struct{})
		for _, certificate := range service.Certificates {
			certificates[normalize(certificate.FingerprintSHA256)] = struct{}{}
		}
		result[serviceKey(service)] = observation{service: service, algorithms: algorithms, certificates: certificates}
	}
	return result
}

func sameCertificates(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if _, exists := right[value]; !exists {
			return false
		}
	}
	return true
}

func serviceKey(service inventory.Service) string {
	return fmt.Sprintf("%s:%d:%s", normalize(service.IP), service.Port, normalize(service.Protocol))
}

func normalize(value string) string { return strings.ToUpper(strings.TrimSpace(value)) }
