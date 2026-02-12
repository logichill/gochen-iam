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
	ctx = WithPermissions(ctx, []string{"a:b", "c:d"})

	set := GetPermissionSet(ctx)
	if set == nil {
		t.Fatalf("expected permission set to be injected")
	}
	if _, ok := set["a:b"]; !ok {
		t.Fatalf("expected a:b in permission set")
	}
	if _, ok := set["c:d"]; !ok {
		t.Fatalf("expected c:d in permission set")
	}
}
