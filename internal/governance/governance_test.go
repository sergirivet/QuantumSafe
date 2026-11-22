package governance

import (
	"net/http/httptest"
	"testing"
)

func TestAuthorizeRoles(t *testing.T) {
	viewer := Principal{Subject: "user-1", TenantID: "tenant-1", Role: RoleViewer}
	if err := Authorize(viewer, PermissionInventoryRead); err != nil {
		t.Fatalf("viewer should read inventory: %v", err)
	}
	if err := Authorize(viewer, PermissionScanCreate); err != ErrForbidden {
		t.Fatalf("viewer should not create scans: %v", err)
	}
	analyst := Principal{Subject: "user-2", TenantID: "tenant-1", Role: RoleAnalyst}
	if err := Authorize(analyst, PermissionScanCreate); err != nil {
		t.Fatalf("analyst should create scans: %v", err)
	}
}

func TestStaticTokenAuthenticator(t *testing.T) {
	principal := Principal{Subject: "service-user", TenantID: "tenant-1", Role: RoleAdmin}
	authenticator, err := NewStaticTokenAuthenticator("secret-token", principal)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("Authorization", "Bearer secret-token")
	got, err := authenticator.Authenticate(request)
	if err != nil || got != principal {
		t.Fatalf("expected authenticated principal, got %+v, %v", got, err)
	}

	request.Header.Set("Authorization", "Bearer wrong-token")
	if _, err := authenticator.Authenticate(request); err != ErrUnauthenticated {
		t.Fatalf("expected unauthenticated error, got %v", err)
	}
}
