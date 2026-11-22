package governance

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Permission string

const (
	PermissionScanCreate    Permission = "scan:create"
	PermissionInventoryRead Permission = "inventory:read"
	PermissionRiskRead      Permission = "risk:read"
	PermissionMigrationRead Permission = "migration:read"
)

type Role string

const (
	RoleViewer  Role = "viewer"
	RoleAnalyst Role = "analyst"
	RoleAdmin   Role = "admin"
)

type Principal struct {
	Subject  string `json:"subject"`
	TenantID string `json:"tenant_id"`
	Role     Role   `json:"role"`
}

var (
	ErrUnauthenticated  = errors.New("unauthenticated")
	ErrForbidden        = errors.New("forbidden")
	ErrInvalidPrincipal = errors.New("invalid principal")
)

func (principal Principal) Validate() error {
	if strings.TrimSpace(principal.Subject) == "" || strings.TrimSpace(principal.TenantID) == "" {
		return ErrInvalidPrincipal
	}
	switch principal.Role {
	case RoleViewer, RoleAnalyst, RoleAdmin:
		return nil
	default:
		return fmt.Errorf("%w: unknown role %q", ErrInvalidPrincipal, principal.Role)
	}
}

func Authorize(principal Principal, permission Permission) error {
	if err := principal.Validate(); err != nil {
		return err
	}
	if principal.Role == RoleAdmin {
		return nil
	}
	switch permission {
	case PermissionInventoryRead, PermissionRiskRead, PermissionMigrationRead:
		return nil
	case PermissionScanCreate:
		if principal.Role == RoleAnalyst {
			return nil
		}
	}
	return ErrForbidden
}

type contextKey struct{}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(contextKey{}).(Principal)
	return principal, ok
}

type Authenticator interface {
	Authenticate(*http.Request) (Principal, error)
}

type StaticTokenAuthenticator struct {
	tokenHash [32]byte
	principal Principal
}

func NewStaticTokenAuthenticator(token string, principal Principal) (*StaticTokenAuthenticator, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("%w: token is required", ErrUnauthenticated)
	}
	if err := principal.Validate(); err != nil {
		return nil, err
	}
	return &StaticTokenAuthenticator{tokenHash: sha256.Sum256([]byte(token)), principal: principal}, nil
}

func (authenticator *StaticTokenAuthenticator) Authenticate(request *http.Request) (Principal, error) {
	const prefix = "Bearer "
	header := request.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return Principal{}, ErrUnauthenticated
	}
	candidate := sha256.Sum256([]byte(strings.TrimSpace(strings.TrimPrefix(header, prefix))))
	if subtle.ConstantTimeCompare(candidate[:], authenticator.tokenHash[:]) != 1 {
		return Principal{}, ErrUnauthenticated
	}
	return authenticator.principal, nil
}

type AuditEvent struct {
	TenantID     string         `json:"tenant_id"`
	Subject      string         `json:"subject"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id,omitempty"`
	Outcome      string         `json:"outcome"`
	OccurredAt   time.Time      `json:"occurred_at"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

type AuditSink interface {
	Append(context.Context, AuditEvent) error
}

type LoggerAuditSink struct{}

func (LoggerAuditSink) Append(context.Context, AuditEvent) error { return nil }
