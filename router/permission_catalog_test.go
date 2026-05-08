package router

import "testing"

func TestRegisterPermissionCatalogRoute(t *testing.T) {
	routes := map[string]struct{}{}
	group := newRecordingGroup("/docs", routes)

	if err := RegisterPermissionCatalogRoute(group, PermissionCatalogOptions{Service: "test"}); err != nil {
		t.Fatalf("RegisterPermissionCatalogRoute failed: %v", err)
	}

	if _, ok := routes["GET /docs/permissions"]; !ok {
		t.Fatalf("expected GET /docs/permissions to be registered, got %#v", routes)
	}
}
