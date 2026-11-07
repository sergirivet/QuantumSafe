package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sergirivet/QuantumSafe/internal/discovery"
	"github.com/sergirivet/QuantumSafe/internal/inventory"
	"github.com/sergirivet/QuantumSafe/internal/migration"
	"github.com/sergirivet/QuantumSafe/internal/pqc"
	"github.com/sergirivet/QuantumSafe/internal/risk"
)

const (
	defaultMaxBodyBytes   = 1 << 20
	defaultRequestTimeout = 30 * time.Second
	defaultPageSize       = 50
	maxPageSize           = 100
)

type Store interface {
	SaveReport(context.Context, discovery.Report) (inventory.ScanRecord, error)
	GetScan(context.Context, int64) (inventory.Snapshot, error)
	GetAsset(context.Context, int64) (inventory.Asset, error)
	ListAssets(context.Context, int, int) ([]inventory.Asset, int, error)
	ListServices(context.Context, int, int) ([]inventory.Service, int, error)
	ListCertificates(context.Context, int, int) ([]inventory.Certificate, int, error)
	ListAlgorithms(context.Context, int, int) ([]inventory.Algorithm, int, error)
}

type Server struct {
	scanner        discovery.Scanner
	store          Store
	logger         *slog.Logger
	maxBodyBytes   int64
	requestTimeout time.Duration
}

type createScanRequest struct {
	Target string `json:"target"`
}

type createScanResponse struct {
	ScanID int64            `json:"scan_id"`
	Report discovery.Report `json:"report"`
}

type pageResponse struct {
	Items    any `json:"items"`
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Total    int `json:"total"`
}

type riskResponse struct {
	ScanID        int64             `json:"scan_id"`
	PolicyVersion string            `json:"policy_version"`
	Assessments   []risk.Assessment `json:"assessments"`
}

type errorResponse struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewServer(scanner discovery.Scanner, store Store) *Server {
	return &Server{
		scanner:        scanner,
		store:          store,
		logger:         slog.Default(),
		maxBodyBytes:   defaultMaxBodyBytes,
		requestTimeout: defaultRequestTimeout,
	}
}

func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/scans", server.handleScans)
	mux.HandleFunc("/api/v1/scans/", server.handleScan)
	mux.HandleFunc("/api/v1/assets", server.handleAssets)
	mux.HandleFunc("/api/v1/assets/", server.handleAsset)
	mux.HandleFunc("/api/v1/services", server.handleServices)
	mux.HandleFunc("/api/v1/certificates", server.handleCertificates)
	mux.HandleFunc("/api/v1/algorithms", server.handleAlgorithms)
	mux.HandleFunc("/api/v1/pqc/readiness", server.handlePQCReadiness)
	mux.HandleFunc("/api/v1/migration/plans", server.handleMigrationPlans)
	mux.HandleFunc("/api/v1/migration/validation", server.handleMigrationValidation)
	return server.withRequestContext(mux)
}

func (server *Server) withRequestContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx, cancel := context.WithTimeout(request.Context(), server.requestTimeout)
		defer cancel()
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func (server *Server) handleScans(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		server.writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if server.store == nil || server.scanner == nil {
		server.writeError(writer, http.StatusServiceUnavailable, "inventory_unavailable", "inventory service is unavailable")
		return
	}

	request.Body = http.MaxBytesReader(writer, request.Body, server.maxBodyBytes)
	var input createScanRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		server.writeError(writer, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}
	if err := ensureSingleJSONValue(decoder); err != nil {
		server.writeError(writer, http.StatusBadRequest, "invalid_json", "request body must contain one JSON object")
		return
	}
	input.Target = strings.TrimSpace(input.Target)
	if input.Target == "" {
		server.writeError(writer, http.StatusBadRequest, "invalid_target", "target is required")
		return
	}

	report, err := server.scanner.Scan(request.Context(), input.Target)
	if err != nil {
		server.logger.ErrorContext(request.Context(), "scan failed", "error", err)
		server.writeError(writer, http.StatusBadRequest, "scan_failed", "target could not be scanned")
		return
	}
	record, err := server.store.SaveReport(request.Context(), report)
	if err != nil {
		server.logger.ErrorContext(request.Context(), "persist scan failed", "error", err)
		server.writeError(writer, http.StatusInternalServerError, "persistence_failed", "scan could not be persisted")
		return
	}

	server.writeJSON(writer, http.StatusCreated, createScanResponse{ScanID: record.ID, Report: report})
}

func (server *Server) handleScan(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		server.writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if server.store == nil {
		server.writeError(writer, http.StatusServiceUnavailable, "inventory_unavailable", "inventory service is unavailable")
		return
	}
	path := strings.TrimPrefix(request.URL.Path, "/api/v1/scans/")
	parts := strings.Split(path, "/")
	if len(parts) == 2 && parts[1] == "risk" {
		server.handleScanRisk(writer, request, parts[0])
		return
	}
	id, ok := server.pathID(request.URL.Path, "/api/v1/scans/")
	if !ok {
		server.writeError(writer, http.StatusBadRequest, "invalid_id", "scan id must be a positive integer")
		return
	}
	snapshot, err := server.store.GetScan(request.Context(), id)
	if err != nil {
		server.handleStoreError(writer, err)
		return
	}
	server.writeJSON(writer, http.StatusOK, snapshot)
}

func (server *Server) handleScanRisk(writer http.ResponseWriter, request *http.Request, rawID string) {
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id < 1 {
		server.writeError(writer, http.StatusBadRequest, "invalid_id", "scan id must be a positive integer")
		return
	}
	snapshot, err := server.store.GetScan(request.Context(), id)
	if err != nil {
		server.handleStoreError(writer, err)
		return
	}
	server.writeJSON(writer, http.StatusOK, riskResponse{
		ScanID:        id,
		PolicyVersion: risk.PolicyVersion,
		Assessments:   risk.AssessSnapshot(snapshot),
	})
}

func (server *Server) handleAssets(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		server.writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if server.store == nil {
		server.writeError(writer, http.StatusServiceUnavailable, "inventory_unavailable", "inventory service is unavailable")
		return
	}
	page, pageSize, offset, ok := parsePage(request)
	if !ok {
		server.writeError(writer, http.StatusBadRequest, "invalid_pagination", "page must be positive and page_size must be between 1 and 100")
		return
	}
	items, total, err := server.store.ListAssets(request.Context(), pageSize, offset)
	if err != nil {
		server.handleStoreError(writer, err)
		return
	}
	server.writeJSON(writer, http.StatusOK, pageResponse{Items: items, Page: page, PageSize: pageSize, Total: total})
}

func (server *Server) handleAsset(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		server.writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if server.store == nil {
		server.writeError(writer, http.StatusServiceUnavailable, "inventory_unavailable", "inventory service is unavailable")
		return
	}
	id, ok := server.pathID(request.URL.Path, "/api/v1/assets/")
	if !ok {
		server.writeError(writer, http.StatusBadRequest, "invalid_id", "asset id must be a positive integer")
		return
	}
	asset, err := server.store.GetAsset(request.Context(), id)
	if err != nil {
		server.handleStoreError(writer, err)
		return
	}
	server.writeJSON(writer, http.StatusOK, asset)
}

func (server *Server) handleServices(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		server.writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if server.store == nil {
		server.writeError(writer, http.StatusServiceUnavailable, "inventory_unavailable", "inventory service is unavailable")
		return
	}
	server.writeServicesPage(writer, request)
}

func (server *Server) handleCertificates(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		server.writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if server.store == nil {
		server.writeError(writer, http.StatusServiceUnavailable, "inventory_unavailable", "inventory service is unavailable")
		return
	}
	page, pageSize, offset, ok := parsePage(request)
	if !ok {
		server.writeError(writer, http.StatusBadRequest, "invalid_pagination", "page must be positive and page_size must be between 1 and 100")
		return
	}
	items, total, err := server.store.ListCertificates(request.Context(), pageSize, offset)
	if err != nil {
		server.handleStoreError(writer, err)
		return
	}
	server.writeJSON(writer, http.StatusOK, pageResponse{Items: items, Page: page, PageSize: pageSize, Total: total})
}

func (server *Server) handleAlgorithms(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		server.writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if server.store == nil {
		server.writeError(writer, http.StatusServiceUnavailable, "inventory_unavailable", "inventory service is unavailable")
		return
	}
	page, pageSize, offset, ok := parsePage(request)
	if !ok {
		server.writeError(writer, http.StatusBadRequest, "invalid_pagination", "page must be positive and page_size must be between 1 and 100")
		return
	}
	items, total, err := server.store.ListAlgorithms(request.Context(), pageSize, offset)
	if err != nil {
		server.handleStoreError(writer, err)
		return
	}
	server.writeJSON(writer, http.StatusOK, pageResponse{Items: items, Page: page, PageSize: pageSize, Total: total})
}

func (server *Server) handlePQCReadiness(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		server.writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if server.store == nil {
		server.writeError(writer, http.StatusServiceUnavailable, "inventory_unavailable", "inventory service is unavailable")
		return
	}
	rawID := request.URL.Query().Get("scan_id")
	scanID, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || scanID < 1 {
		server.writeError(writer, http.StatusBadRequest, "invalid_id", "scan_id must be a positive integer")
		return
	}
	snapshot, err := server.store.GetScan(request.Context(), scanID)
	if err != nil {
		server.handleStoreError(writer, err)
		return
	}
	server.writeJSON(writer, http.StatusOK, pqc.AssessSnapshot(snapshot))
}

func (server *Server) handleMigrationPlans(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		server.writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if server.store == nil {
		server.writeError(writer, http.StatusServiceUnavailable, "inventory_unavailable", "inventory service is unavailable")
		return
	}
	rawID := request.URL.Query().Get("scan_id")
	scanID, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || scanID < 1 {
		server.writeError(writer, http.StatusBadRequest, "invalid_id", "scan_id must be a positive integer")
		return
	}
	snapshot, err := server.store.GetScan(request.Context(), scanID)
	if err != nil {
		server.handleStoreError(writer, err)
		return
	}
	server.writeJSON(writer, http.StatusOK, migration.Build(snapshot))
}

func (server *Server) handleMigrationValidation(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		server.writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if server.store == nil {
		server.writeError(writer, http.StatusServiceUnavailable, "inventory_unavailable", "inventory service is unavailable")
		return
	}
	baselineID, currentID, ok := parseValidationIDs(request)
	if !ok {
		server.writeError(writer, http.StatusBadRequest, "invalid_id", "baseline_scan_id and current_scan_id must be positive integers")
		return
	}
	baseline, err := server.store.GetScan(request.Context(), baselineID)
	if err != nil {
		server.handleStoreError(writer, err)
		return
	}
	current, err := server.store.GetScan(request.Context(), currentID)
	if err != nil {
		server.handleStoreError(writer, err)
		return
	}
	server.writeJSON(writer, http.StatusOK, migration.Validate(baseline, current))
}

func (server *Server) writeServicesPage(writer http.ResponseWriter, request *http.Request) {
	page, pageSize, offset, ok := parsePage(request)
	if !ok {
		server.writeError(writer, http.StatusBadRequest, "invalid_pagination", "page must be positive and page_size must be between 1 and 100")
		return
	}
	items, total, err := server.store.ListServices(request.Context(), pageSize, offset)
	if err != nil {
		server.handleStoreError(writer, err)
		return
	}
	server.writeJSON(writer, http.StatusOK, pageResponse{Items: items, Page: page, PageSize: pageSize, Total: total})
}

func (server *Server) handleStoreError(writer http.ResponseWriter, err error) {
	if errors.Is(err, inventory.ErrNotFound) {
		server.writeError(writer, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	server.logger.Error("inventory request failed", "error", err)
	server.writeError(writer, http.StatusInternalServerError, "internal_error", "internal server error")
}

func (server *Server) pathID(path, prefix string) (int64, bool) {
	value := strings.TrimPrefix(path, prefix)
	if value == path || value == "" || strings.Contains(value, "/") {
		return 0, false
	}
	id, err := strconv.ParseInt(value, 10, 64)
	return id, err == nil && id > 0
}

func parsePage(request *http.Request) (int, int, int, bool) {
	values := request.URL.Query()
	page := 1
	pageSize := defaultPageSize
	var err error
	if values.Get("page") != "" {
		page, err = strconv.Atoi(values.Get("page"))
		if err != nil || page < 1 {
			return 0, 0, 0, false
		}
	}
	if values.Get("page_size") != "" {
		pageSize, err = strconv.Atoi(values.Get("page_size"))
		if err != nil || pageSize < 1 || pageSize > maxPageSize {
			return 0, 0, 0, false
		}
	}
	return page, pageSize, (page - 1) * pageSize, true
}

func parseValidationIDs(request *http.Request) (int64, int64, bool) {
	baselineID, baselineErr := strconv.ParseInt(request.URL.Query().Get("baseline_scan_id"), 10, 64)
	currentID, currentErr := strconv.ParseInt(request.URL.Query().Get("current_scan_id"), 10, 64)
	return baselineID, currentID, baselineErr == nil && currentErr == nil && baselineID > 0 && currentID > 0
}

func ensureSingleJSONValue(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("unexpected additional JSON value")
	}
	return nil
}

func (server *Server) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		server.logger.Error("write JSON response failed", "error", err)
	}
}

func (server *Server) writeError(writer http.ResponseWriter, status int, code, message string) {
	server.writeJSON(writer, status, errorResponse{Error: apiError{Code: code, Message: message}})
}
