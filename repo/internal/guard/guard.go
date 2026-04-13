package guard

import (
	"strconv"
	"strings"

	"gochen/authz"
	"gochen/errorx"
)

func RequirePair(
	writeGuard authz.WriteGuard,
	ownerKind string,
	ownerID int64,
	relatedKind string,
	relatedID int64,
) (authz.ResourceWriteGuard, authz.ResourceWriteGuard, error) {
	owner, err := writeGuard.RequireResource(strings.TrimSpace(ownerKind), FormatInt64(ownerID))
	if err != nil {
		return authz.ResourceWriteGuard{}, authz.ResourceWriteGuard{}, err
	}
	related, err := writeGuard.RequireResource(strings.TrimSpace(relatedKind), FormatInt64(relatedID))
	if err != nil {
		return authz.ResourceWriteGuard{}, authz.ResourceWriteGuard{}, err
	}
	if err := RequireSameTenant(owner, related); err != nil {
		return authz.ResourceWriteGuard{}, authz.ResourceWriteGuard{}, err
	}
	return owner, related, nil
}

func RequireSameTenant(resources ...authz.ResourceWriteGuard) error {
	var tenantID string
	for _, resource := range resources {
		currentTenantID := strings.TrimSpace(resource.DataScope.TenantID)
		if currentTenantID == "" {
			continue
		}
		if tenantID == "" {
			tenantID = currentTenantID
			continue
		}
		if tenantID != currentTenantID {
			return errorx.New(errorx.Forbidden, "write guard resources must belong to the same tenant")
		}
	}
	return nil
}

func FormatInt64(id int64) string {
	return strconv.FormatInt(id, 10)
}
