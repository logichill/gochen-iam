package router

import (
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	scoperepo "gochen-iam/repo/scope"
	svc "gochen-iam/service"
	scopesvc "gochen-iam/service/scope"
	"gochen/errors"
	"gochen/httpx"
)

// ScopeRoutes 授权域治理路由。
type ScopeRoutes struct {
	scopeRepo    *scoperepo.ScopeRepo
	scopeService *scopesvc.ScopeService
}

func NewScopeRoutes(scopeRepo *scoperepo.ScopeRepo, scopeService *scopesvc.ScopeService) *ScopeRoutes {
	return &ScopeRoutes{
		scopeRepo:    scopeRepo,
		scopeService: scopeService,
	}
}

func (sr *ScopeRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "route group cannot be nil")
	}
	scopeGroup := group.Group("/scopes")
	scopeGroup.Use(iammw.PlatformScopeMiddleware())
	scopeGroup.Use(iammw.AdminOnlyMiddleware())

	scopeGroup.GET("", sr.listScopes)
	scopeGroup.GET("/:id/visibility", sr.getScopeVisibility)
	scopeGroup.POST("", sr.createScope)
	scopeGroup.PUT("/:id", sr.updateScope)
	scopeGroup.POST("/:id/activate", sr.activateScope)
	scopeGroup.POST("/:id/deactivate", sr.deactivateScope)
	scopeGroup.POST("/:id/repair", sr.repairScope)
	scopeGroup.DELETE("/:id", sr.deleteScope)
	return nil
}

func (sr *ScopeRoutes) Name() string {
	return "scope"
}

func (sr *ScopeRoutes) Priority() int {
	return 60
}

func (sr *ScopeRoutes) listScopes(ctx httpx.IContext) error {
	items, err := sr.scopeRepo.List(ctx.RequestContext())
	if err != nil {
		return err
	}
	result := make([]svc.ScopeListItem, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		governance := &svc.ScopeGovernanceState{}
		if sr.scopeService != nil {
			state, err := sr.scopeService.ScopeGovernanceState(ctx.RequestContext(), item.ID)
			if err != nil {
				return err
			}
			governance = state
		}
		result = append(result, toScopeListItem(item, governance))
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
	visibleScopeIDs, err := sr.scopeRepo.VisibleScopeIDs(ctx.RequestContext(), scopeID)
	if err != nil {
		return err
	}
	items := make([]svc.ScopeListItem, 0, len(visibleScopeIDs))
	for _, visibleScopeID := range visibleScopeIDs {
		scope, err := sr.scopeRepo.Get(ctx.RequestContext(), visibleScopeID)
		if err != nil {
			if errors.Is(err, errors.NotFound) {
				continue
			}
			return err
		}
		items = append(items, toScopeListItem(scope, nil))
	}
	return httpx.WriteSuccess(ctx, &svc.ScopeVisibilityResponse{
		ViewerScopeID:   scopeID,
		VisibleScopeIDs: visibleScopeIDs,
		VisibleScopes:   items,
	})
}

func (sr *ScopeRoutes) createScope(ctx httpx.IContext) error {
	if sr.scopeService == nil {
		return errors.NewCode(errors.Internal, "scope service is not configured")
	}
	req := &svc.CreateScopeRequest{}
	if err := ctx.BindJSON(req); err != nil {
		return err
	}
	scope, err := sr.scopeService.CreateScope(ctx.RequestContext(), req)
	if err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, toScopeListItem(scope, nil))
}

func (sr *ScopeRoutes) updateScope(ctx httpx.IContext) error {
	if sr.scopeService == nil {
		return errors.NewCode(errors.Internal, "scope service is not configured")
	}
	scopeID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}
	req := &svc.UpdateScopeRequest{}
	if err := ctx.BindJSON(req); err != nil {
		return err
	}
	scope, err := sr.scopeService.UpdateScope(ctx.RequestContext(), scopeID, req)
	if err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, toScopeListItem(scope, nil))
}

func (sr *ScopeRoutes) activateScope(ctx httpx.IContext) error {
	if sr.scopeService == nil {
		return errors.NewCode(errors.Internal, "scope service is not configured")
	}
	scopeID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}
	if err := sr.scopeService.ActivateScope(ctx.RequestContext(), scopeID); err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, map[string]any{
		"id":     scopeID,
		"status": iamentity.ScopeStatusActive,
	})
}

func (sr *ScopeRoutes) deactivateScope(ctx httpx.IContext) error {
	if sr.scopeService == nil {
		return errors.NewCode(errors.Internal, "scope service is not configured")
	}
	scopeID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}
	if err := sr.scopeService.DeactivateScope(ctx.RequestContext(), scopeID); err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, map[string]any{
		"id":     scopeID,
		"status": iamentity.ScopeStatusInactive,
	})
}

func (sr *ScopeRoutes) deleteScope(ctx httpx.IContext) error {
	if sr.scopeService == nil {
		return errors.NewCode(errors.Internal, "scope service is not configured")
	}
	scopeID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}
	if err := sr.scopeService.DeleteScope(ctx.RequestContext(), scopeID); err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, map[string]any{
		"id": scopeID,
	})
}

func (sr *ScopeRoutes) repairScope(ctx httpx.IContext) error {
	if sr.scopeService == nil {
		return errors.NewCode(errors.Internal, "scope service is not configured")
	}
	scopeID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}
	scope, err := sr.scopeService.RepairScope(ctx.RequestContext(), scopeID)
	if err != nil {
		return err
	}
	governance, err := sr.scopeService.ScopeGovernanceState(ctx.RequestContext(), scopeID)
	if err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, toScopeListItem(scope, governance))
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
