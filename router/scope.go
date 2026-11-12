package router

import (
	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	scopesvc "gochen-iam/service/scope"
	runtimehttp "gochen-runtime/http"
	"gochen/errors"
	"gochen/httpx"
)

// ScopeRoutes 授权域治理路由。
type ScopeRoutes struct {
	scopeService *scopesvc.ScopeService
}

func NewScopeRoutes(scopeService *scopesvc.ScopeService) (*ScopeRoutes, error) {
	if scopeService == nil {
		return nil, errors.NewCode(errors.InvalidInput, "scope routes require the declared scope service")
	}
	if _, err := scopeService.AuthorizationBinding("list"); err != nil {
		return nil, err
	}
	return &ScopeRoutes{scopeService: scopeService}, nil
}

func (sr *ScopeRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "route group cannot be nil")
	}
	scopeGroup := group.Group("/scopes")
	registry, _, err := runtimehttp.EntryRegistryFrom(scopeGroup)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		method, path, action string
		handler              httpx.Handler
	}{
		{"GET", "", "list", sr.listScopes},
		{"GET", "/:id/visibility", "visibility", sr.getScopeVisibility},
		{"POST", "", "create", sr.createScope},
		{"PUT", "/:id", "update", sr.updateScope},
		{"POST", "/:id/activate", "activate", sr.activateScope},
		{"POST", "/:id/deactivate", "deactivate", sr.deactivateScope},
		{"POST", "/:id/repair", "repair", sr.repairScope},
		{"DELETE", "/:id", "delete", sr.deleteScope},
	} {
		binding, err := sr.scopeService.AuthorizationBinding(entry.action)
		if err != nil {
			return err
		}
		if registry != nil {
			if err := runtimehttp.BindEntry(scopeGroup, entry.method, entry.path, binding); err != nil {
				return err
			}
		}
		if err := runtimehttp.RegisterRoute(scopeGroup, entry.method, entry.path, entry.handler); err != nil {
			return err
		}
	}
	return nil
}

func (sr *ScopeRoutes) Name() string {
	return "scope"
}

func (sr *ScopeRoutes) Priority() int {
	return 60
}

func (sr *ScopeRoutes) listScopes(ctx httpx.IContext) error {
	out, err := sr.scopeService.ExecuteHTTP(ctx.RequestContext(), "list", scopesvc.ScopeCommandInput{})
	if err != nil {
		return err
	}
	result := make([]svc.ScopeListItem, 0, len(out.Items))
	for _, item := range out.Items {
		result = append(result, toScopeListItem(item.Scope, item.Governance))
	}
	return httpx.WriteSuccess(ctx, map[string]any{
		"items": result,
		"total": len(result),
	})
}

func (sr *ScopeRoutes) getScopeVisibility(ctx httpx.IContext) error {
	scopeID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}
	out, err := sr.scopeService.ExecuteHTTP(ctx.RequestContext(), "visibility", scopesvc.ScopeCommandInput{ID: scopeID})
	if err != nil {
		return err
	}
	items := make([]svc.ScopeListItem, 0, len(out.VisibleItems))
	for _, scope := range out.VisibleItems {
		items = append(items, toScopeListItem(scope, nil))
	}
	return httpx.WriteSuccess(ctx, &svc.ScopeVisibilityResponse{
		ViewerScopeID:   scopeID,
		VisibleScopeIDs: out.VisibleIDs,
		VisibleScopes:   items,
	})
}

func (sr *ScopeRoutes) createScope(ctx httpx.IContext) error {
	req := &svc.CreateScopeRequest{}
	if err := ctx.BindJSON(req); err != nil {
		return err
	}
	out, err := sr.scopeService.ExecuteHTTP(ctx.RequestContext(), "create", scopesvc.ScopeCommandInput{Create: req})
	if err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, toScopeListItem(out.Scope, nil))
}

func (sr *ScopeRoutes) updateScope(ctx httpx.IContext) error {
	scopeID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}
	req := &svc.UpdateScopeRequest{}
	if err := ctx.BindJSON(req); err != nil {
		return err
	}
	out, err := sr.scopeService.ExecuteHTTP(ctx.RequestContext(), "update", scopesvc.ScopeCommandInput{ID: scopeID, Update: req})
	if err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, toScopeListItem(out.Scope, nil))
}

func (sr *ScopeRoutes) activateScope(ctx httpx.IContext) error {
	scopeID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}
	if _, err := sr.scopeService.ExecuteHTTP(ctx.RequestContext(), "activate", scopesvc.ScopeCommandInput{ID: scopeID}); err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, map[string]any{
		"id":     scopeID,
		"status": iamentity.ScopeStatusActive,
	})
}

func (sr *ScopeRoutes) deactivateScope(ctx httpx.IContext) error {
	scopeID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}
	if _, err := sr.scopeService.ExecuteHTTP(ctx.RequestContext(), "deactivate", scopesvc.ScopeCommandInput{ID: scopeID}); err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, map[string]any{
		"id":     scopeID,
		"status": iamentity.ScopeStatusInactive,
	})
}

func (sr *ScopeRoutes) deleteScope(ctx httpx.IContext) error {
	scopeID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}
	if _, err := sr.scopeService.ExecuteHTTP(ctx.RequestContext(), "delete", scopesvc.ScopeCommandInput{ID: scopeID}); err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, map[string]any{
		"id": scopeID,
	})
}

func (sr *ScopeRoutes) repairScope(ctx httpx.IContext) error {
	scopeID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}
	out, err := sr.scopeService.ExecuteHTTP(ctx.RequestContext(), "repair", scopesvc.ScopeCommandInput{ID: scopeID})
	if err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, toScopeListItem(out.Scope, out.Governance))
}

func toScopeListItem(scope *iamentity.Scope, governance *svc.ScopeGovernanceState) svc.ScopeListItem {
	item := svc.ScopeListItem{
		ID:          scope.ID,
		Key:         scope.Key,
		Name:        scope.Name,
		Type:        scope.Type,
		ParentID:    scope.ParentID,
		Path:        scope.Path,
		Depth:       scope.Depth,
		Status:      scope.Status,
		Description: scope.Description,
	}
	if governance != nil {
		item.ChildCount = governance.ChildCount
		item.CanDelete = governance.CanDelete
		item.DeleteBlockReason = governance.DeleteBlockReason
		item.HealthStatus = governance.HealthStatus
		item.HealthReason = governance.HealthReason
		item.CanRepair = governance.CanRepair
	}
	return item
}
