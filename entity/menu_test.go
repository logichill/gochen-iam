package entity

import (
	"testing"

	"gochen/errors"
)

func TestMenuItemValidateRejectsBlankPermission(t *testing.T) {
	item := &MenuItem{
		Code:             "dashboard",
		Title:            "Dashboard",
		Type:             MenuTypePage,
		AllOfPermissions: StringArray{"   "},
	}

	if err := item.Validate(); err == nil || !errors.Is(err, errors.Validation) {
		t.Fatalf("expected validation error for blank menu permission, got %v", err)
	}
}
