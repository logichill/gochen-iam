package router

import (
	"context"
	"testing"

	iamentity "gochen-iam/entity"
	domaincrud "gochen/domain/crud"
	"gochen/errorx"
)

type groupHookRepoStub struct {
	groups  map[int64]*iamentity.Group
	updated []*iamentity.Group
}

var _ domaincrud.IRepository[*iamentity.Group, int64] = (*groupHookRepoStub)(nil)

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
		return nil, errorx.New(errorx.NotFound, "组织不存在")
	}
	cp := *g
	return &cp, nil
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
	if err := hooks.BeforeCreate(context.Background(), child); err != nil {
		t.Fatalf("BeforeCreate: %v", err)
	}
	if child.Level != 2 {
		t.Fatalf("expected child level 2, got %d", child.Level)
	}
	if child.Parent == nil || child.Parent.GetID() != parent.GetID() {
		t.Fatalf("expected child parent to be populated")
	}
	if len(repo.updated) != 0 {
		t.Fatalf("expected hooks not to persist during BeforeCreate, got %#v", repo.updated)
	}
}

func TestGroupCRUDHooks_UpdateParentRecomputesLevelAndPath(t *testing.T) {
	root := &iamentity.Group{}
	root.SetID(1)
	root.Level = 1
	root.Path = "/1"

	child := &iamentity.Group{}
	child.SetID(2)
	child.Level = 1
	child.Path = "/2"

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

	if err := hooks.BeforeUpdate(context.Background(), updating); err != nil {
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
