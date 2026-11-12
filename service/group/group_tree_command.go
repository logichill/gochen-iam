package group

import (
	"context"

	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	svc "gochen-iam/service"
	"gochen/app"
	"gochen/app/query"
	"gochen/auth"
	"gochen/domain/spec"
	"gochen/errors"
)

type groupTreeAccess struct {
	groups *app.CommandReader[int, []*iamentity.Group]
	counts *app.CommandReader[[]int64, map[int64]int64]
}
type groupTreeCommand = app.Command[struct{}, groupTreeAccess, []*svc.GroupTreeNode]

func (s *GroupService) compileTreeCommands() error {
	s.treeCommands = map[string]*groupTreeCommand{}
	for _, action := range []string{"tree", "http_tree"} {
		var policies []auth.IPolicy
		if action == "http_tree" {
			policies = []auth.IPolicy{groupAssociationEntryPolicy{}}
		}
		resources := make([]app.CommandResource[struct{}], 0, 2)
		for _, resource := range []struct {
			name, kind, path string
			provider         app.IExecutionDescriptorProvider
		}{
			{"groups", svc.GroupResourceKind, "CommandReader -> complete group pages with group spec before pagination, without preloads", s.groupRepo},
			{"members", svc.UserResourceKind, "CommandReader -> IDs from authorized group pages -> ScopedQueryWithSpec -> user_groups join -> member counts", s.userRepo},
		} {
			descriptor := auth.Descriptor{Resource: resource.kind, Actions: []auth.Action{{Name: action, Kind: auth.KindList, Permission: svc.GroupPermissionSet.Code(iamperm.ActionRead)}}}
			authorizer, err := s.authorizer.Compile(descriptor, resource.provider.ExecutionDescriptor().Metadata(), policies...)
			if err != nil {
				return err
			}
			resources = append(resources, app.CommandResource[struct{}]{Name: resource.name, Repository: resource.provider, Authorizer: authorizer, Action: action, ConditionPath: resource.path,
				Intent: func(struct{}) (auth.Request, error) { return auth.Request{}, nil },
			})
		}
		command, err := app.NewCommand(app.CommandOptions[struct{}, groupTreeAccess, []*svc.GroupTreeNode]{Resources: resources,
			Access: func(_ context.Context, _ struct{}, grants []*app.CommandGrant) (groupTreeAccess, error) {
				return s.bindTreeAccess(action, grants)
			}, Handler: func(ctx context.Context, _ struct{}, access groupTreeAccess) ([]*svc.GroupTreeNode, error) {
				var groups []*iamentity.Group
				nodes := map[int64]*svc.GroupTreeNode{}
				for offset := 0; ; offset += 1000 {
					page, err := access.groups.Read(ctx, offset)
					if err != nil {
						return nil, err
					}
					ids := make([]int64, 0, len(page))
					for _, group := range page {
						ids = append(ids, group.GetID())
					}
					counts, err := access.counts.Read(ctx, ids)
					if err != nil {
						return nil, err
					}
					for _, group := range page {
						nodes[group.GetID()] = &svc.GroupTreeNode{ID: group.GetID(), Name: group.Name, Description: group.Description, Level: group.Level, UserCount: int(counts[group.GetID()])}
					}
					groups = append(groups, page...)
					if len(page) < 1000 {
						break
					}
				}
				var roots []*svc.GroupTreeNode
				for _, group := range groups {
					node := nodes[group.GetID()]
					if group.ParentID == nil {
						roots = append(roots, node)
					} else if parent := nodes[*group.ParentID]; parent != nil {
						parent.Children = append(parent.Children, node)
					}
				}
				return roots, nil
			}})
		if err != nil {
			return err
		}
		s.treeCommands[action] = command
	}
	return nil
}

func (s *GroupService) bindTreeAccess(action string, grants []*app.CommandGrant) (groupTreeAccess, error) {
	var access groupTreeAccess
	if len(grants) != 2 {
		return access, errors.NewCode(errors.InvalidInput, "group tree requires group and membership grants")
	}
	for i, resource := range []struct{ name, kind string }{{"groups", svc.GroupResourceKind}, {"members", svc.UserResourceKind}} {
		if grants[i] == nil || grants[i].Name() != resource.name {
			return access, errors.NewCode(errors.InvalidInput, "group tree grant differs from its declaration")
		}
		req, err := grants[i].Request()
		if err != nil {
			return access, err
		}
		if req.Resource != resource.kind || req.Action != action {
			return access, errors.NewCode(errors.InvalidInput, "group tree action differs from its declaration")
		}
	}
	allowedIDs := map[int64]bool{}
	var err error
	access.groups, err = app.NewCommandReader(s.groupRepo, grants[0], func(ctx context.Context, offset int, condition spec.Spec) ([]*iamentity.Group, error) {
		if offset < 0 {
			return nil, errors.NewCode(errors.InvalidInput, "group page offset must be nonnegative")
		}
		groups, err := s.groupRepo.Query(ctx, query.QueryOptions{Offset: offset, Limit: 1000, Sorts: []query.Sort{{Field: "level", Direction: query.ASC}, {Field: "name", Direction: query.ASC}, {Field: "id", Direction: query.ASC}}}, condition)
		if err != nil {
			return nil, err
		}
		for _, group := range groups {
			allowedIDs[group.GetID()] = true
		}
		return groups, nil
	})
	if err != nil {
		return access, err
	}
	access.counts, err = app.NewCommandReader(s.userRepo, grants[1], func(ctx context.Context, ids []int64, condition spec.Spec) (map[int64]int64, error) {
		for _, id := range ids {
			if !allowedIDs[id] {
				return nil, errors.NewCode(errors.Forbidden, "member count group is outside the authorized group pages")
			}
		}
		return s.userRepo.GroupMemberCounts(ctx, ids, condition)
	})
	return access, err
}

func (s *GroupService) GroupTreeHTTP(ctx context.Context) ([]*svc.GroupTreeNode, error) {
	return s.treeCommands["http_tree"].Execute(ctx, struct{}{})
}

func (s *GroupService) TreeAuthorizationBinding() (auth.EntryBinding, error) {
	return s.treeCommands["http_tree"].AuthorizationBinding()
}
