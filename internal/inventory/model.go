package inventory

import (
	"errors"
	"time"

	"github.com/sergirivet/QuantumSafe/internal/discovery"
)

var ErrNotFound = errors.New("inventory record not found")

type ScanRecord struct {
	ID int64 `json:"id"`
}

type Snapshot struct {
	ID                 int64     `json:"id"`
	Target             string    `json:"target"`
	SchemaVersion      int       `json:"schema_version"`
	ScannedAt          time.Time `json:"scanned_at"`
	DurationMS         int64     `json:"duration_ms"`
	AddressesTruncated bool      `json:"addresses_truncated"`
	Addresses          []string  `json:"addresses"`
	Asset              Asset     `json:"asset"`
}

type Asset struct {
	ID       int64     `json:"id"`
	Name     string    `json:"name"`
	Services []Service `json:"services,omitempty"`
}

type Service struct {
	ID           int64         `json:"id"`
	AssetID      int64         `json:"asset_id"`
	AssetName    string        `json:"asset_name,omitempty"`
	IP           string        `json:"ip"`
	Port         int           `json:"port"`
	Protocol     string        `json:"protocol"`
	Certificates []Certificate `json:"certificates,omitempty"`
	Algorithms   []Algorithm   `json:"algorithms,omitempty"`
}

type Certificate struct {
	ID                 int64     `json:"id"`
	FingerprintSHA256  string    `json:"fingerprint_sha256"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	DNSNames           []string  `json:"dns_names"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
}

type Algorithm struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

func AlgorithmsFromService(service discovery.Service) []Algorithm {
	if service.TLS == nil {
		return nil
	}

	algorithms := make([]Algorithm, 0, 2)
	if service.TLS.Version != "" {
		algorithms = append(algorithms, Algorithm{Name: service.TLS.Version, Category: "tls_version"})
	}
	if service.TLS.CipherSuite != "" {
		algorithms = append(algorithms, Algorithm{Name: service.TLS.CipherSuite, Category: "cipher_suite"})
	}
	if service.TLS.PublicKeyAlgorithm != "" {
		algorithms = append(algorithms, Algorithm{Name: service.TLS.PublicKeyAlgorithm, Category: "public_key"})
	}
	return algorithms
}
