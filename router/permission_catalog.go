package router

import (
	"os"

	iammw "gochen-iam/middleware"
	"gochen/errors"
	"gochen/httpx"
)

// PermissionCatalogOptions controls the permission catalog response.
type PermissionCatalogOptions struct {
	Service         string
	ExposeCallsites bool
}

// RegisterPermissionCatalogRoute registers GET /permissions on the given route group.
func RegisterPermissionCatalogRoute(group httpx.IRouteGroup, options PermissionCatalogOptions) error {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "route group cannot be nil")
	}

	service := options.Service
	if service == "" {
		service = "iam"
	}

	group.GET("/permissions", func(ctx httpx.IContext) error {
		resp := map[string]any{
			"service":                         service,
			"required_permissions":            iammw.RequiredPermissions(),
			"required_permission_definitions": iammw.RequiredPermissionDefinitions(),
		}
		if shouldExposePermissionCallsites(options.ExposeCallsites) {
			resp["required_permissions_callsites"] = iammw.RequiredPermissionsWithRedactedCallsites()
		}
		return httpx.WriteSuccess(ctx, resp)
	})
	return nil
}

func shouldExposePermissionCallsites(explicit bool) bool {
	if explicit {
		return true
	}
	if !iammw.IsDevEnv() {
		return false
	}
	value := os.Getenv("AUTH_EXPOSE_PERMISSION_CALLSITES")
	return value == "true" || value == "1"
}
