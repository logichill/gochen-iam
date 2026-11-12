package router

import (
	"context"

	iamentity "gochen-iam/entity"
	tenantrepo "gochen-iam/repo/tenant"
	svc "gochen-iam/service"
	"gochen/app"
	appcrud "gochen/app/crud"
	"gochen/app/query"
	"gochen/db/orm"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

// Core owns normalization, transactions and versions. Its private port combines
// the current grant with Core's final condition without transporting opaque Specs.
type tenantCRUDRepository struct {
	*tenantrepo.TenantRepo
	grant  *app.CommandGrant
	action string
	access *tenantCRUDAccess
}

func (a *tenantCRUDApplication) bindPrimary(action string, access *tenantCRUDAccess, grant *app.CommandGrant) (*tenantCRUDRepository, error) {
	if _, err := app.NewCommandReader(a.routes.tenantRepo, grant, func(context.Context, struct{}, spec.Spec) (struct{}, error) { return struct{}{}, nil }); err != nil {
		return nil, err
	}
	return &tenantCRUDRepository{TenantRepo: a.routes.tenantRepo, grant: grant, action: action, access: access}, nil
}
func (r *tenantCRUDRepository) Get(ctx context.Context, id int64, coreCondition spec.Spec) (*iamentity.Tenant, error) {
	reader, err := app.NewCommandReader(r.TenantRepo, r.grant, func(ctx context.Context, id int64, condition spec.Spec) (*iamentity.Tenant, error) {
		if !r.access.known[id] {
			return nil, errors.NewCode(errors.Forbidden, "tenant read is outside the declared targets")
		}
		item, err := r.TenantRepo.Get(ctx, id, spec.And(condition, coreCondition))
		if err == nil {
			err = r.access.remember(item)
		}
		return item, err
	})
	if err != nil {
		return nil, err
	}
	return reader.Read(ctx, id)
}
func (r *tenantCRUDRepository) Query(ctx context.Context, options query.QueryOptions, coreCondition spec.Spec) ([]*iamentity.Tenant, error) {
	reader, err := app.NewCommandReader(r.TenantRepo, r.grant, func(ctx context.Context, options query.QueryOptions, condition spec.Spec) ([]*iamentity.Tenant, error) {
		if r.action != appcrud.ActionList {
			return nil, errors.NewCode(errors.Forbidden, "tenant query differs from declaration")
		}
		items, err := r.TenantRepo.Query(ctx, options, spec.And(condition, coreCondition))
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			r.access.known[item.ID] = true
			// Sparse selection remains a response choice; resource relations use a
			// complete, conditioned snapshot of each actual returned tenant.
			trusted := item
			if len(options.Fields) > 0 {
				trusted, err = r.TenantRepo.Get(ctx, item.ID, spec.And(condition, coreCondition))
				if err != nil {
					return nil, err
				}
			}
			if err := r.access.remember(trusted); err != nil {
				return nil, err
			}
		}
		return items, nil
	})
	if err != nil {
		return nil, err
	}
	return reader.Read(ctx, options)
}
func (r *tenantCRUDRepository) QueryCount(ctx context.Context, options query.QueryOptions, coreCondition spec.Spec) (int64, error) {
	reader, err := app.NewCommandReader(r.TenantRepo, r.grant, func(ctx context.Context, options query.QueryOptions, condition spec.Spec) (int64, error) {
		if r.action != appcrud.ActionList {
			return 0, errors.NewCode(errors.Forbidden, "tenant count differs from declaration")
		}
		return r.TenantRepo.QueryCount(ctx, options, spec.And(condition, coreCondition))
	})
	if err != nil {
		return 0, err
	}
	return reader.Read(ctx, options)
}
func (r *tenantCRUDRepository) apply(ctx context.Context, item *iamentity.Tenant, coreCondition spec.Spec, operation string) error {
	writer, err := app.NewCommandWriter(r.TenantRepo, r.grant, func(ctx context.Context, item *iamentity.Tenant, condition spec.Spec) (*iamentity.Tenant, error) {
		if item == nil || operation != r.action {
			return nil, errors.NewCode(errors.Forbidden, "tenant write differs from declaration")
		}
		if operation != appcrud.ActionCreate && !r.access.known[item.ID] {
			return nil, errors.NewCode(errors.Forbidden, "tenant write is outside declared targets")
		}
		condition = spec.And(condition, coreCondition)
		var err error
		switch operation {
		case appcrud.ActionCreate:
			err = r.TenantRepo.Create(ctx, item, condition)
		case appcrud.ActionUpdate:
			err = r.TenantRepo.Update(ctx, item, condition)
		case appcrud.ActionDelete:
			err = r.TenantRepo.Delete(ctx, item, condition)
		}
		if err == nil {
			r.access.known[item.ID] = true
			err = r.access.remember(item)
		}
		return item, err
	})
	if err != nil {
		return err
	}
	result, err := writer.Write(ctx, item)
	if err == nil {
		*item = *result
	}
	return err
}
func (r *tenantCRUDRepository) Create(ctx context.Context, item *iamentity.Tenant, condition spec.Spec) error {
	return r.apply(ctx, item, condition, appcrud.ActionCreate)
}
func (r *tenantCRUDRepository) Update(ctx context.Context, item *iamentity.Tenant, condition spec.Spec) error {
	return r.apply(ctx, item, condition, appcrud.ActionUpdate)
}
func (r *tenantCRUDRepository) Delete(ctx context.Context, item *iamentity.Tenant, condition spec.Spec) error {
	return r.apply(ctx, item, condition, appcrud.ActionDelete)
}

func (a *tenantCRUDApplication) bindGovernance(action string, access *tenantCRUDAccess, grants map[string]*app.CommandGrant) error {
	tr := a.routes
	for _, name := range []string{"users", "groups", "roles"} {
		grant := grants[name]
		if grant == nil {
			continue
		}
		resource := app.IExecutionDescriptorProvider(tr.userRepo.Repo)
		if name == "groups" {
			resource = tr.groupRepo.Repo
		}
		if name == "roles" {
			resource = tr.roleRepo.Repo
		}
		reader, err := app.NewCommandReader(resource, grant, func(ctx context.Context, key string, condition spec.Spec) (int64, error) {
			if !access.trustedKey(key) {
				return 0, errors.NewCode(errors.Forbidden, "tenant occupancy key differs from trusted tenant")
			}
			// Occupancy is a complete catalog of this trusted tenant, including
			// users whose home tenant differs from their current isolation key.
			if !condition.IsAll() {
				return 0, errors.NewCode(errors.Forbidden, "tenant occupancy requires the complete authorized catalog")
			}
			switch name {
			case "users":
				model, err := tr.userRepo.ModelFor(ctx)
				if err != nil {
					return 0, err
				}
				return model.Count(ctx, orm.WithWhere("(tenant_id = ? OR home_tenant_id = ?) AND deleted_at IS NULL", key, key))
			case "groups":
				model, err := tr.groupRepo.ModelFor(ctx)
				if err != nil {
					return 0, err
				}
				return model.Count(ctx, orm.WithWhere("tenant_id = ? AND deleted_at IS NULL", key))
			default:
				model, err := tr.roleRepo.ModelFor(ctx)
				if err != nil {
					return 0, err
				}
				return model.Count(ctx, orm.WithWhere("tenant_id = ? AND deleted_at IS NULL", key))
			}
		})
		if err != nil {
			return err
		}
		switch name {
		case "users":
			access.governance.countUsers = reader.Read
		case "groups":
			access.governance.countGroups = reader.Read
		case "roles":
			access.governance.countRoles = reader.Read
		}
	}
	rootGrant := grants["root"]
	if rootGrant == nil {
		return nil
	}
	get, err := app.NewCommandReader(tr.scopeRepo.Repo, rootGrant, func(ctx context.Context, id int64, condition spec.Spec) (*iamentity.Scope, error) {
		if !access.trustedRoot(id) {
			return nil, errors.NewCode(errors.Forbidden, "scope differs from trusted tenant root reference")
		}
		root, err := tr.scopeRepo.Repo.Get(ctx, id, condition)
		if err == nil {
			frozen, cloneErr := meta.Clone(*root)
			if cloneErr != nil {
				return nil, cloneErr
			}
			access.roots[id] = frozen
		}
		return root, err
	})
	if err != nil {
		return err
	}
	access.governance.getScope = get.Read
	children, err := app.NewCommandReader(tr.scopeRepo.Repo, rootGrant, func(ctx context.Context, id int64, condition spec.Spec) (int64, error) {
		root, exists := access.roots[id]
		if !exists || !access.ownsRoot(root) {
			return 0, errors.NewCode(errors.Forbidden, "child count requires a trusted tenant root")
		}
		return tr.scopeRepo.Repo.QueryCount(ctx, query.QueryOptions{}, spec.And(condition, spec.Eq(meta.ByField("ParentID"), id)))
	})
	if err != nil {
		return err
	}
	access.governance.countScopeChild = children.Read
	deletedRoot := false
	remove, err := app.NewCommandWriter(tr.scopeRepo.Repo, rootGrant, func(ctx context.Context, root *iamentity.Scope, condition spec.Spec) (struct{}, error) {
		if action != appcrud.ActionDelete || root == nil {
			return struct{}{}, errors.NewCode(errors.Forbidden, "root delete differs from declaration")
		}
		trusted, exists := access.roots[root.ID]
		if !exists || !access.ownsRoot(trusted) || root.Key != trusted.Key || root.Type != iamentity.ScopeTypeTenant || root.Version != trusted.Version {
			return struct{}{}, errors.NewCode(errors.Forbidden, "root delete differs from trusted scope")
		}
		condition = spec.And(condition, svc.PlatformWriteSpec(ctx), spec.Eq(meta.ByField("Key"), trusted.Key), spec.Eq(meta.ByField("Type"), iamentity.ScopeTypeTenant))
		if err := tr.scopeRepo.Delete(ctx, root, condition); err != nil {
			return struct{}{}, errors.Wrap(err, errors.Database, "删除租户 root scope 失败")
		}
		deletedRoot = true
		return struct{}{}, nil
	})
	if err != nil {
		return err
	}
	access.governance.deleteScope = func(ctx context.Context, root *iamentity.Scope) error { _, err := remove.Write(ctx, root); return err }
	visibility, err := app.NewCommandWriter(a.visibility, grants["visibility"], func(ctx context.Context, _ struct{}, condition spec.Spec) (struct{}, error) {
		if action != appcrud.ActionDelete || !deletedRoot || !condition.IsAll() || a.visibility.owner != tr.scopeRepo.Repo {
			return struct{}{}, errors.NewCode(errors.Forbidden, "visibility rebuild requires this command's successful root delete")
		}
		deletedRoot = false
		return struct{}{}, tr.scopeRepo.RebuildVisibilityMap(ctx)
	})
	if err != nil {
		return err
	}
	access.governance.rebuildScopeGraph = func(ctx context.Context) error { _, err := visibility.Write(ctx, struct{}{}); return err }
	access.catalog, err = app.NewCommandWriter(tr.scopeRepo.Repo, rootGrant, func(ctx context.Context, in tenantCatalogCall, condition spec.Spec) (tenantCatalogResult, error) {
		trusted, exists := access.trusted[in.ID]
		if !exists {
			return tenantCatalogResult{}, errors.NewCode(errors.Forbidden, "tenant catalog target has no trusted snapshot")
		}
		for _, guard := range access.guards {
			if _, err := guard.Read(ctx, struct{}{}); err != nil {
				return tenantCatalogResult{}, err
			}
		}
		if !condition.IsAll() || a.visibility.owner != tr.scopeRepo.Repo {
			return tenantCatalogResult{}, errors.NewCode(errors.Forbidden, "tenant native catalog requires its complete actual source")
		}
		tenants, scopes, err := tr.scopeAuthorizer.TenantScopeProviders()
		if err != nil {
			return tenantCatalogResult{}, err
		}
		if tenants != tr.tenantRepo.Repo || scopes != tr.scopeRepo.Repo {
			return tenantCatalogResult{}, errors.NewCode(errors.InvalidInput, "tenant native catalog source changed")
		}
		// Keep private snapshots independent from the native helper's mutable draft.
		tenant, err := meta.Clone(trusted)
		if err != nil {
			return tenantCatalogResult{}, err
		}
		switch in.Operation {
		case "provision":
			if action != appcrud.ActionCreate || grants["link"] == nil {
				return tenantCatalogResult{}, errors.NewCode(errors.Forbidden, "tenant root provisioning differs from declaration")
			}
			root, err := tr.scopeAuthorizer.EnsureTenantRootScope(ctx, &tenant)
			return tenantCatalogResult{Root: root}, err
		case "health":
			if action != appcrud.ActionRead && action != appcrud.ActionList && action != appcrud.ActionUpdate {
				return tenantCatalogResult{}, errors.NewCode(errors.Forbidden, "tenant root health differs from declaration")
			}
			health, err := tr.scopeAuthorizer.TenantRootScopeHealth(ctx, &tenant)
			return tenantCatalogResult{Health: health}, err
		default:
			return tenantCatalogResult{}, errors.NewCode(errors.InvalidInput, "unknown tenant catalog operation")
		}
	})
	return err
}

func (a *tenantCRUDApplication) project(ctx context.Context, access *tenantCRUDAccess, items []*iamentity.Tenant) (tenantCRUDResult, error) {
	out := tenantCRUDResult{Items: items, Views: make([]svc.TenantListItem, 0, len(items))}
	for _, item := range items {
		trusted, exists := access.trusted[item.ID]
		if !exists {
			return tenantCRUDResult{}, errors.NewCode(errors.Forbidden, "tenant projection requires an actual command target")
		}
		view := tenantListItem(item)
		state, err := access.governance.State(ctx, &trusted)
		if err != nil {
			return tenantCRUDResult{}, err
		}
		view.CanDelete, view.DeleteBlockReason = state.CanDelete, state.DeleteBlockReason
		health, err := access.catalog.Write(ctx, tenantCatalogCall{ID: item.ID, Operation: "health"})
		if err != nil {
			return tenantCRUDResult{}, err
		}
		if health.Health != nil {
			view.RootScopeStatus, view.RootScopeReason, view.CanRepairRootScope = health.Health.Status, health.Health.Reason, health.Health.CanRepair
		}
		out.Views = append(out.Views, view)
	}
	return out, nil
}
