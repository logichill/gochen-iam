package service

import "testing"

func TestAllPermissionDefinitions_IncludeActionAndMenuVisibilityPatterns(t *testing.T) {
	assertContainsDefinition := func(code string) {
		t.Helper()
		for _, def := range AllPermissionDefinitions {
			if def.Code == code {
				return
			}
		}
		t.Fatalf("expected permission definition %q to be registered", code)
	}

	assertContainsDefinition("action:mcp:invoke")
	assertContainsDefinition("menu:*:view")
}
