package auth

import (
	"context"
	"testing"

	hbasic "gochen/httpx/nethttp"
)

func TestWithPermissions_InjectsPermissionSet(t *testing.T) {
	ctx, err := hbasic.NewRequestContext(context.Background())
	if err != nil {
		t.Fatalf("NewRequestContext: %v", err)
	}
	ctx = WithPermissions(ctx, []string{"api:a:read", "api:c:write"})

	set := PermissionSet(ctx)
	if set == nil {
		t.Fatalf("expected permission set to be injected")
	}
	if _, ok := set["api:a:read"]; !ok {
		t.Fatalf("expected api:a:read in permission set")
	}
	if _, ok := set["api:c:write"]; !ok {
		t.Fatalf("expected api:c:write in permission set")
	}
}
