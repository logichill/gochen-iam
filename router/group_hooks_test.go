package router

import (
	"context"
	"os"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	auth "gochen-runtime/host/authz"
	"gochen/auth/scoped"

	"gochen/contextx"
	"gochen/errors"
)

func TestMain(m *testing.M) {
	os.Setenv("IAM_TENANT_MODE", "tenant")
	os.Exit(m.Run())
}

type groupHookRepoStub struct {
	groups  map[int64]*iamentity.Group
	updated []*iamentity.Group
}

var _ svc.IResourceContextRepository[*iamentity.Group, int64] = (*groupHookRepoStub)(nil)

func (s *groupHookRepoStub) Create(context.Context, *iamentity.Group) error { return nil }

func (s *groupHookRepoStub) Update(_ context.Context, g *iamentity.Group) error {
	cp := *g
	s.groups[g.GetID()] = &cp
	s.updated = append(s.updated, &cp)
	return nil
}

func (s *groupHookRepoStub) Delete(context.Context, int64) error { return nil }

func (s *groupHookRepoStub) Get(_ context.Context, id int64) (*iamentity.Group, error) {
	g, ok := s.groups[id]
	if !ok {
		return nil, errors.NewCode(errors.NotFound, "组织不存在")
	}
	cp := *g
	return &cp, nil
}

func (s *groupHookRepoStub) ResolveResourceByID(_ context.Context, id int64) (scoped.Resource, error) {
	g, ok := s.groups[id]
	if !ok {
		return scoped.Resource{}, errors.NewCode(errors.NotFound, "组织不存在")
	}
	return scoped.Resource{
		Kind:    "iam.group",
		ID:      "group",
		OwnerID: "tenant:" + g.GetTenantID(),
	}, nil
}

func tenantCtx(t *testing.T, tenantID string) context.Context {
	t.Helper()
	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:     1,
		ActiveScopeID: 1,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = contextx.WithTenantID(ctx, tenantID)
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, string(iamentity.ScopeTypeTenant))
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(1))
	if err != nil {
		t.Fatalf("WithDataScope: %v", err)
	}
	return ctx
}

func TestGroupCRUDHooks_CreateChildSetsLevelAndParent(t *testing.T) {
	parent := &iamentity.Group{}
	parent.SetID(1)
	parent.Level = 1
	parent.Path = "/1"

	repo := &groupHookRepoStub{
		groups: map[int64]*iamentity.Group{
			1: parent,
		},
	}
	hooks := newGroupCRUDHooks(repo)

	parentID := int64(1)
	child := &iamentity.Group{
		Name:     "管理员",
		ParentID: &parentID,
	}
	ctx := tenantCtx(t, "tenant-1")
	if err := hooks.BeforeCreate(ctx, child); err != nil {
		t.Fatalf("BeforeCreate: %v", err)
	}
	if child.Level != 2 {
		t.Fatalf("expected child level 2, got %d", child.Level)
	}
	if child.Parent == nil || child.Parent.GetID() != parent.GetID() {
		t.Fatalf("expected child parent to be populated")
	}
	if child.GetTenantID() != "tenant-1" {
		t.Fatalf("expected tenant_id tenant-1, got %s", child.GetTenantID())
	}
	if len(repo.updated) != 0 {
		t.Fatalf("expected hooks not to persist during BeforeCreate, got %#v", repo.updated)
	}
}

func TestGroupCRUDHooks_UpdateParentRecomputesLevelAndPath(t *testing.T) {
	const tid = "tenant-1"
	root := &iamentity.Group{}
	root.SetID(1)
	root.Level = 1
	root.Path = "/1"
	root.SetTenantID(tid)

	child := &iamentity.Group{}
	child.SetID(2)
	child.Level = 1
	child.Path = "/2"
	child.SetTenantID(tid)

	repo := &groupHookRepoStub{
		groups: map[int64]*iamentity.Group{
			1: root,
			2: child,
		},
	}
	hooks := newGroupCRUDHooks(repo)

	parentID := int64(1)
	updating := &iamentity.Group{}
	*updating = *child
	updating.ParentID = &parentID

	ctx := tenantCtx(t, tid)
	if err := hooks.BeforeUpdate(ctx, updating); err != nil {
		t.Fatalf("BeforeUpdate: %v", err)
	}
	if updating.Level != 2 {
		t.Fatalf("expected level 2 after reparent, got %d", updating.Level)
	}
	wantPath := "/1/2"
	if updating.Path != wantPath {
		t.Fatalf("expected path %s after reparent, got %s", wantPath, updating.Path)
	}
}

func TestGroupCRUDHooks_DeleteCrossTenantRejected(t *testing.T) {
	g := &iamentity.Group{}
	g.SetID(1)
	g.SetTenantID("tenant-a")

	repo := &groupHookRepoStub{
		groups: map[int64]*iamentity.Group{1: g},
	}
	hooks := newGroupCRUDHooks(repo)

	ctx := tenantCtx(t, "tenant-b")
	err := hooks.BeforeDelete(ctx, 1)
	if !errors.Is(err, errors.Forbidden) {
		t.Fatalf("expected Forbidden error for cross-tenant delete, got %v", err)
	}
}

func TestGroupCRUDHooks_DeleteSameTenantAllowed(t *testing.T) {
	g := &iamentity.Group{}
	g.SetID(1)
	g.SetTenantID("tenant-a")

	repo := &groupHookRepoStub{
		groups: map[int64]*iamentity.Group{1: g},
	}
	hooks := newGroupCRUDHooks(repo)

	ctx := tenantCtx(t, "tenant-a")
	if err := hooks.BeforeDelete(ctx, 1); err != nil {
		t.Fatalf("expected no error for same-tenant delete, got %v", err)
	}
}
