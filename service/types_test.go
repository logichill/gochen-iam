package service

import (
	"testing"

	iammw "gochen-iam/middleware"
)

func TestFieldPatchApply(t *testing.T) {
	t.Run("unset keeps original value", func(t *testing.T) {
		current := "keep"
		patch := FieldPatch[string]{}
		if err := patch.Apply(&current); err != nil {
			t.Fatalf("apply empty patch: %v", err)
		}
		if current != "keep" {
			t.Fatalf("expected original value to stay unchanged, got %q", current)
		}
	})

	t.Run("set pointer replaces value", func(t *testing.T) {
		current := int64Ptr(1)
		next := int64Ptr(99)
		patch := ValueFieldPatch(func(target **int64, value *int64) {
			*target = value
		}, next)
		if err := patch.Apply(&current); err != nil {
			t.Fatalf("apply patch: %v", err)
		}
		if !sameInt64Ptr(current, next) {
			t.Fatalf("expected pointer %v, got %v", next, current)
		}
	})

	t.Run("apply multiple patches in order", func(t *testing.T) {
		type sample struct {
			Name  string
			Level int
		}

		target := sample{Name: "old", Level: 1}
		if err := ApplyFieldPatches(
			&target,
			ValueFieldPatch(func(target *sample, value string) { target.Name = value }, "new"),
			ValueFieldPatch(func(target *sample, value int) { target.Level = value }, 2),
		); err != nil {
			t.Fatalf("ApplyFieldPatches: %v", err)
		}
		if target.Name != "new" || target.Level != 2 {
			t.Fatalf("unexpected target after patches: %+v", target)
		}
	})
}

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

func TestAllPermissionDefinitions_IncludeRiskLevelsForHighRiskPermissions(t *testing.T) {
	assertRiskLevel := func(code string, expected string) {
		t.Helper()
		for _, def := range AllPermissionDefinitions {
			if def.Code != code {
				continue
			}
			if def.RiskLevel != expected {
				t.Fatalf("expected %s risk %q, got %q", code, expected, def.RiskLevel)
			}
			return
		}
		t.Fatalf("expected permission definition %q to be registered", code)
	}

	assertRiskLevel("api:plan:write", string(iammw.RiskLevelHigh))
	assertRiskLevel("api:tenant:write", string(iammw.RiskLevelCritical))
	assertRiskLevel("action:mcp:invoke", string(iammw.RiskLevelCritical))
}

func TestAllPermissionDefinitions_IncludeBuiltinOnlyWildcardPermissions(t *testing.T) {
	assertBuiltinOnly := func(code string) {
		t.Helper()
		for _, def := range AllPermissionDefinitions {
			if def.Code != code {
				continue
			}
			if !def.BuiltinOnly {
				t.Fatalf("expected %s to be builtin-only", code)
			}
			return
		}
		t.Fatalf("expected permission definition %q to be registered", code)
	}

	assertBuiltinOnly("menu:*:view")
	assertBuiltinOnly("api:*:*")
	assertBuiltinOnly("*:*:*")
}

func int64Ptr(v int64) *int64 {
	return &v
}
