package service

import (
	"context"
	"strings"

	iamentity "gochen-iam/entity"
	"gochen/app"
	"gochen/app/query"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

// TenantScopeProviders returns the actual repositories used to resolve a tenant root.
func (a *ScopeAuthorizer) TenantScopeProviders() (app.IExecutionDescriptorProvider, app.IExecutionDescriptorProvider, error) {
	if a == nil || a.tenantRepo == nil || a.tenantRepo.Repo == nil || a.scopeRepo == nil || a.scopeRepo.Repo == nil {
		return nil, nil, errors.NewCode(errors.InvalidInput, "tenant scope resolution requires its actual tenant and scope repositories")
	}
	return a.tenantRepo.Repo, a.scopeRepo.Repo, nil
}

// TenantScopeReader consumes declared tenant/root capabilities in one invocation.
type TenantScopeReader struct {
	tenant *app.CommandReader[struct{}, *iamentity.Tenant]
	root   *app.CommandReader[int64, *iamentity.Scope]
	rootID int64
}

func (a *ScopeAuthorizer) BindTenantScopeReader(tenantGrant, scopeGrant *app.CommandGrant) (*TenantScopeReader, error) {
	if _, _, err := a.TenantScopeProviders(); err != nil {
		return nil, err
	}
	reader := &TenantScopeReader{}
	var err error
	reader.tenant, err = app.NewCommandReader(a.tenantRepo.Repo, tenantGrant, func(ctx context.Context, _ struct{}, condition spec.Spec) (*iamentity.Tenant, error) {
		key, err := TenantIDFromContext(ctx)
		if err != nil {
			return nil, err
		}
		items, err := a.tenantRepo.Repo.Query(ctx, query.QueryOptions{Limit: 1}, spec.And(condition, spec.Eq(meta.ByField("Key"), key)))
		if err != nil {
			return nil, err
		}
		if len(items) != 1 || strings.TrimSpace(items[0].Key) != key {
			return nil, errors.NewCode(errors.NotFound, "租户不存在")
		}
		if items[0].RootScopeID == nil || *items[0].RootScopeID <= 0 {
			return nil, errors.NewCode(errors.Internal, "tenant root scope is missing")
		}
		reader.rootID = *items[0].RootScopeID
		return items[0], nil
	})
	if err != nil {
		return nil, err
	}
	reader.root, err = app.NewCommandReader(a.scopeRepo.Repo, scopeGrant, func(ctx context.Context, id int64, condition spec.Spec) (*iamentity.Scope, error) {
		if id <= 0 || id != reader.rootID {
			return nil, errors.NewCode(errors.Forbidden, "root scope differs from the trusted tenant relation")
		}
		root, err := a.scopeRepo.Repo.Get(ctx, id, condition)
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.Internal, "tenant root scope is missing")
		}
		return root, err
	})
	return reader, err
}

func (r *TenantScopeReader) Read(ctx context.Context) (*iamentity.Scope, error) {
	if r == nil || r.tenant == nil || r.root == nil {
		return nil, errors.NewCode(errors.InvalidInput, "tenant scope reader is required")
	}
	tenant, err := r.tenant.Read(ctx, struct{}{})
	if err != nil {
		return nil, err
	}
	root, err := r.root.Read(ctx, r.rootID)
	if err != nil {
		return nil, err
	}
	if root.Key != "tenant:"+strings.TrimSpace(tenant.Key) || root.Type != iamentity.ScopeTypeTenant {
		return nil, errors.NewCode(errors.Internal, "tenant root scope is inconsistent")
	}
	return root, nil
}
