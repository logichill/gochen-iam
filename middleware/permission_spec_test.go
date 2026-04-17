package middleware

import "testing"

func TestJoinActions_DeduplicatesAndPreservesOrder(t *testing.T) {
	actions := JoinActions(
		ReadWriteDeleteActions(),
		[]Action{ActionWrite, ActionSelfRead},
		SelfActions(),
	)

	expected := []Action{
		ActionRead,
		ActionWrite,
		ActionDelete,
		ActionSelfRead,
		ActionSelfEdit,
	}
	if len(actions) != len(expected) {
		t.Fatalf("expected %d actions, got %d: %#v", len(expected), len(actions), actions)
	}
	for i := range expected {
		if actions[i] != expected[i] {
			t.Fatalf("expected action[%d]=%q, got %q", i, expected[i], actions[i])
		}
	}
}

func TestAPIPermissions_BuildsExpectedSpecs(t *testing.T) {
	specs := APIPermissions(ResourceUser, JoinActions(ManageActions(), SelfActions())...)

	if len(specs) != 6 {
		t.Fatalf("expected 6 specs, got %d", len(specs))
	}

	read := PermissionByAction(specs, ActionRead)
	if read.Code != "api:user:read" {
		t.Fatalf("expected read permission code api:user:read, got %q", read.Code)
	}

	selfEdit := PermissionByAction(specs, ActionSelfEdit)
	if selfEdit.Code != "api:user:update_self" {
		t.Fatalf("expected self edit permission code api:user:update_self, got %q", selfEdit.Code)
	}
}

func TestPermissionCodes_DeduplicatesSpecs(t *testing.T) {
	specs := JoinPermissionSpecs(
		APIPermissions(ResourceTask, ReadWriteDeleteActions()...),
		APIPermissions(ResourceTask, ActionRead, ActionWrite),
	)

	codes := PermissionCodes(specs...)
	expected := []string{"api:task:read", "api:task:write", "api:task:delete"}
	if len(codes) != len(expected) {
		t.Fatalf("expected %d codes, got %d: %#v", len(expected), len(codes), codes)
	}
	for i := range expected {
		if codes[i] != expected[i] {
			t.Fatalf("expected code[%d]=%q, got %q", i, expected[i], codes[i])
		}
	}
}

func TestPermissionSet_CodeAndMustExposeActionIndexedAccess(t *testing.T) {
	set := NewAPIPermissionSet(ResourceUser, JoinActions(ManageActions(), SelfActions())...)

	if got := set.Code(ActionRead); got != "api:user:read" {
		t.Fatalf("expected read code api:user:read, got %q", got)
	}
	if got := set.Must(ActionSelfEdit).Code; got != "api:user:update_self" {
		t.Fatalf("expected self edit code api:user:update_self, got %q", got)
	}
	if got := len(set.Codes()); got != 6 {
		t.Fatalf("expected 6 codes, got %d", got)
	}
}

func TestPermissionSpecDefinitionUsesCoreNormalization(t *testing.T) {
	def := ApiPermission(ResourceUser, ActionWrite).
		Label(" User Write ").
		Desc(" Update user ").
		Scope(ScopeTenant, ScopeTenant).
		Builtin().
		Risk(RiskLevelHigh).
		Definition()

	if def.Code != "api:user:write" {
		t.Fatalf("expected normalized code, got %q", def.Code)
	}
	if def.Name != "User Write" || def.Description != "Update user" {
		t.Fatalf("expected normalized metadata, got %#v", def)
	}
	if len(def.Scopes) != 1 || def.Scopes[0] != string(ScopeTenant) {
		t.Fatalf("expected deduplicated scopes, got %#v", def.Scopes)
	}
	if !def.BuiltinOnly || def.RiskLevel != string(RiskLevelHigh) {
		t.Fatalf("expected builtin high-risk definition, got %#v", def)
	}
}
