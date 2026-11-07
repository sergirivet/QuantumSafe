package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sergirivet/QuantumSafe/internal/discovery"
	"github.com/sergirivet/QuantumSafe/internal/inventory"
)

func TestCreateScanReturnsCreatedReport(t *testing.T) {
	store := &fakeStore{}
	server := NewServer(fakeScanner{report: discovery.Report{Target: "example.com"}}, store)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{"target":"example.com"}`))
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var response createScanResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.ScanID != 7 || response.Report.Target != "example.com" || !store.saved {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestCreateScanRejectsUnknownJSONField(t *testing.T) {
	server := NewServer(fakeScanner{}, &fakeStore{})

	request := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{"target":"example.com","secret":"do-not-accept"}`))
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}
	assertAPIError(t, recorder, "invalid_json")
}

func TestGetScanReturnsNotFound(t *testing.T) {
	server := NewServer(fakeScanner{}, &fakeStore{getScanErr: inventory.ErrNotFound})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/scans/99", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}
	assertAPIError(t, recorder, "not_found")
}

func TestListAssetsUsesPagination(t *testing.T) {
	store := &fakeStore{assets: []inventory.Asset{{ID: 1, Name: "example.com"}}, total: 9}
	server := NewServer(fakeScanner{}, store)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/assets?page=2&page_size=3", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if store.limit != 3 || store.offset != 3 {
		t.Fatalf("unexpected pagination: limit=%d offset=%d", store.limit, store.offset)
	}
}

func TestGetScanRiskReturnsVersionedAssessment(t *testing.T) {
	store := &fakeStore{snapshot: inventory.Snapshot{
		ID:     9,
		Target: "payments-api",
		Asset: inventory.Asset{
			Name: "payments-api",
			Services: []inventory.Service{{
				ID:       2,
				IP:       "203.0.113.10",
				Port:     443,
				Protocol: "https",
				Algorithms: []inventory.Algorithm{{
					Name: "ECDSA P-256", Category: "public_key",
				}},
			}},
		},
	}}
	server := NewServer(fakeScanner{}, store)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/scans/9/risk", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var response riskResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode risk response: %v", err)
	}
	if response.PolicyVersion == "" || len(response.Assessments) != 1 {
		t.Fatalf("unexpected risk response: %+v", response)
	}
}

func TestGetPQCReadinessRequiresScanIDAndUsesEvidence(t *testing.T) {
	store := &fakeStore{snapshot: inventory.Snapshot{
		ID:     9,
		Target: "payments-api",
		Asset: inventory.Asset{
			Name: "payments-api",
			Services: []inventory.Service{{
				ID:         2,
				IP:         "203.0.113.10",
				Port:       443,
				Protocol:   "https",
				Algorithms: []inventory.Algorithm{{Name: "ML-KEM-768", Category: "kem"}},
			}},
		},
	}}
	server := NewServer(fakeScanner{}, store)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/pqc/readiness?scan_id=9", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Catalog string `json:"catalog"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode readiness response: %v", err)
	}
	if response.Catalog == "" {
		t.Fatal("expected catalog version")
	}
}

func TestGetMigrationPlansReturnsProposedItems(t *testing.T) {
	store := &fakeStore{snapshot: inventory.Snapshot{
		ID:     9,
		Target: "payments-api",
		Asset: inventory.Asset{
			Name: "payments-api",
			Services: []inventory.Service{{
				ID:         2,
				IP:         "203.0.113.10",
				Port:       443,
				Protocol:   "https",
				Algorithms: []inventory.Algorithm{{Name: "ECDSA", Category: "public_key"}},
			}},
		},
	}}
	server := NewServer(fakeScanner{}, store)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/migration/plans?scan_id=9", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Items []struct {
			Status string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode migration response: %v", err)
	}
	if len(response.Items) != 1 || response.Items[0].Status != "proposed" {
		t.Fatalf("unexpected migration response: %+v", response)
	}
}

func TestGetMigrationValidationComparesTwoScans(t *testing.T) {
	server := NewServer(fakeScanner{}, &fakeStore{snapshot: inventory.Snapshot{
		ID:     1,
		Target: "payments-api",
		Asset:  inventory.Asset{Name: "payments-api"},
	}})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/migration/validation?baseline_scan_id=1&current_scan_id=2", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode validation response: %v", err)
	}
	if response.Status != "inconclusive" {
		t.Fatalf("expected inconclusive empty comparison, got %q", response.Status)
	}
}

func TestCreateScanEnforcesBodyLimit(t *testing.T) {
	server := NewServer(fakeScanner{}, &fakeStore{})
	server.maxBodyBytes = 8

	request := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{"target":"example.com"}`))
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}
}

func assertAPIError(t *testing.T, recorder *httptest.ResponseRecorder, code string) {
	t.Helper()
	var response errorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if response.Error.Code != code {
		t.Fatalf("expected error code %q, got %q", code, response.Error.Code)
	}
}

type fakeScanner struct {
	report discovery.Report
	err    error
}

func (scanner fakeScanner) Scan(context.Context, string) (discovery.Report, error) {
	if scanner.err != nil {
		return discovery.Report{}, scanner.err
	}
	return scanner.report, nil
}

type fakeStore struct {
	saved      bool
	getScanErr error
	snapshot   inventory.Snapshot
	assets     []inventory.Asset
	total      int
	limit      int
	offset     int
}

func (store *fakeStore) SaveReport(context.Context, discovery.Report) (inventory.ScanRecord, error) {
	store.saved = true
	return inventory.ScanRecord{ID: 7}, nil
}

func (store *fakeStore) GetScan(context.Context, int64) (inventory.Snapshot, error) {
	if store.getScanErr != nil {
		return inventory.Snapshot{}, store.getScanErr
	}
	if store.snapshot.ID != 0 {
		return store.snapshot, nil
	}
	return inventory.Snapshot{ID: 7, Target: "example.com"}, nil
}

func (store *fakeStore) GetAsset(context.Context, int64) (inventory.Asset, error) {
	return inventory.Asset{ID: 1, Name: "example.com"}, nil
}

func (store *fakeStore) ListAssets(_ context.Context, limit, offset int) ([]inventory.Asset, int, error) {
	store.limit = limit
	store.offset = offset
	return store.assets, store.total, nil
}

func (store *fakeStore) ListServices(context.Context, int, int) ([]inventory.Service, int, error) {
	return []inventory.Service{}, 0, nil
}

func (store *fakeStore) ListCertificates(context.Context, int, int) ([]inventory.Certificate, int, error) {
	return []inventory.Certificate{}, 0, nil
}

func (store *fakeStore) ListAlgorithms(context.Context, int, int) ([]inventory.Algorithm, int, error) {
	return []inventory.Algorithm{}, 0, nil
}
