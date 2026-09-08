package auth

import (
	"context"
	"testing"

	"gochen/httpx"
)

func TestWithPermissions_InjectsPermissionSet(t *testing.T) {
	ctx, err := httpx.NewRequestContext(context.Background())
	if err != nil {
		t.Fatalf("NewRequestContext: %v", err)
	}
	ctx = WithPermissions(ctx, []string{"a:api:read", "c:api:write"})

	set := PermissionSet(ctx)
	if set == nil {
		t.Fatalf("expected permission set to be injected")
	}
	if _, ok := set["a:api:read"]; !ok {
		t.Fatalf("expected a:api:read in permission set")
	}
	if _, ok := set["c:api:write"]; !ok {
		t.Fatalf("expected c:api:write in permission set")
	}
}
