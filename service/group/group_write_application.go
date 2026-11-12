package group

import (
	"context"
	"strconv"
	"strings"

	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	svc "gochen-iam/service"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	appcrud "gochen/app/crud"
	"gochen/app/query"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

type groupWriteInput struct{ IDs []int64 }
type groupDirectoryQuery struct {
	Operation string
	ID        int64
	Name      string
	ParentID  *int64
}
type groupWriteAccess struct {
	primary                       *app.CommandGrant
	before                        map[int64]*iamentity.Group
	directory                     *app.CommandReader[groupDirectoryQuery, []*iamentity.Group]
	duplicates                    *app.CommandReader[groupDirectoryQuery, bool]
	links                         *app.CommandReader[int64, []int64]
	subtree                       *app.CommandRepository[*iamentity.Group, int64]
	known                         map[int64]bool
	staged                        map[int64][]*iamentity.Group
	parents                       map[int64]*iamentity.Group
	scope                         *svc.TenantScopeReader
	childrenExists, membersExists *app.CommandReader[int64, bool]
}

// groupWriteApplication binds each invocation's capabilities to private hooks.
// The Core CRUD application owns validation, protected fields, versions and transactions.
type groupWriteApplication struct {
	*appcrud.Application[*iamentity.Group, int64]
	service   *GroupService
	options   appcrud.Options[*iamentity.Group, int64]
	resources map[string][]app.CommandResource[groupWriteInput]
}

func (s *GroupService) compileWriteApplications() error {
	for _, http := range []bool{false, true} {
		options := appcrud.Options[*iamentity.Group, int64]{Resource: "group", ActionPermissions: map[string]string{
			appcrud.ActionRead: svc.GroupPermissionSet.Code(iamperm.ActionRead), appcrud.ActionList: svc.GroupPermissionSet.Code(iamperm.ActionRead),
			appcrud.ActionCreate: svc.GroupPermissionSet.Code(iamperm.ActionWrite), appcrud.ActionUpdate: svc.GroupPermissionSet.Code(iamperm.ActionWrite),
			appcrud.ActionDelete: svc.GroupPermissionSet.Code(iamperm.ActionDelete),
		}}
		descriptor, err := appcrud.Describe(options, true)
		if err != nil {
			return err
		}
		var policies []auth.IPolicy
		if http {
			policies = []auth.IPolicy{groupAssociationEntryPolicy{}}
		}
		options.Authorizer, err = s.authorizer.Compile(descriptor, s.groupRepo.Repo.ExecutionDescriptor().Metadata(), policies...)
		if err != nil {
			return err
		}
		core, err := appcrud.NewApplication(s.groupRepo.Repo, options)
		if err != nil {
			return err
		}
		executor := &groupWriteApplication{Application: core, service: s, options: options, resources: map[string][]app.CommandResource[groupWriteInput]{}}
		for _, action := range []string{appcrud.ActionCreate, appcrud.ActionUpdate, appcrud.ActionDelete} {
			resources := []struct {
				name, resource string
				kind           auth.Kind
			}{
				{"group", "group", auth.KindCreate},
				{"directory", svc.GroupResourceKind, auth.KindList},
				{"duplicates", "iam.group.name_directory", auth.KindList},
			}
			if action == appcrud.ActionUpdate {
				resources[0].kind = auth.KindUpdate
				resources = append(resources, struct {
					name, resource string
					kind           auth.Kind
				}{"links", "iam.group.hierarchy_links", auth.KindList}, struct {
					name, resource string
					kind           auth.Kind
				}{"subtree", svc.GroupResourceKind, auth.KindUpdate})
			}
			if action == appcrud.ActionDelete {
				resources = []struct {
					name, resource string
					kind           auth.Kind
				}{
					{"group", "group", auth.KindDelete},
					{"children_exists", "iam.group.children_exists", auth.KindRead},
					{"members_exists", "iam.group.members_exists", auth.KindRead},
				}
			}
			var tenants, scopes app.IExecutionDescriptorProvider
			if action == appcrud.ActionCreate && s.scopeAuthorizer != nil {
				tenants, scopes, err = s.scopeAuthorizer.TenantScopeProviders()
				if err != nil {
					return err
				}
				resources = append(resources, struct {
					name, resource string
					kind           auth.Kind
				}{"tenant_scope", "iam.group.tenant_scope", auth.KindRead}, struct {
					name, resource string
					kind           auth.Kind
				}{"root_scope", "iam.group.root_scope", auth.KindRead})
			}
			for _, resource := range resources {
				provider := app.IExecutionDescriptorProvider(s.groupRepo.Repo)
				if resource.name == "tenant_scope" {
					provider = tenants
				} else if resource.name == "root_scope" {
					provider = scopes
				} else if resource.name == "members_exists" {
					provider = s.userRepo.Repo
				} else if action == appcrud.ActionDelete && resource.name == "group" {
					provider = s.groupRepo
				}
				name := action + "_" + resource.name
				if resource.name == "group" {
					name = action
				}
				permission := svc.GroupPermissionSet.Code(iamperm.ActionWrite)
				if action == appcrud.ActionDelete {
					permission = svc.GroupPermissionSet.Code(iamperm.ActionDelete)
				}
				d := auth.Descriptor{Resource: resource.resource, Actions: []auth.Action{{Name: name, Kind: resource.kind, Permission: permission}}}
				var authorizer *auth.Authorizer
				if resource.name == "group" {
					// The same complete plan drives Core CRUD, REST's initial read and
					// the primary command grant for the write action.
					authorizer = options.Authorizer.(*auth.Authorizer)
				} else if resource.name == "links" || resource.name == "duplicates" || resource.name == "tenant_scope" || resource.name == "root_scope" || strings.HasSuffix(resource.name, "_exists") {
					// A tenant-local ID projection preserves the existing complete subtree
					// traversal. Every resulting node must pass the separate write grant.
					authorizer, err = auth.Compile(auth.Declaration{Descriptor: d, ResourceAccess: auth.ResourceAccessData,
						Rules: []auth.Rule{{ID: resource.resource, System: auth.SystemCheckConstraints, UnauthorizedAsDenial: true, Constraints: policies}}},
						auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: provider.ExecutionDescriptor().Metadata()})
				} else {
					authorizer, err = s.authorizer.Compile(d, provider.ExecutionDescriptor().Metadata(), policies...)
				}
				if err != nil {
					return err
				}
				primary := resource.name == "group"
				binding := app.CommandResource[groupWriteInput]{Name: resource.name,
					Repository: provider, Authorizer: authorizer, Action: name,
					ConditionPath: "app.Command -> private Core CRUD hooks -> conditioned group directory; trusted tenant-local child IDs -> every subtree node conditioned and frozen before any write",
					Intent: func(in groupWriteInput) (auth.Request, error) {
						if !primary || action == appcrud.ActionCreate {
							return auth.Request{}, nil
						}
						ids := make([]string, 0, len(in.IDs))
						for _, id := range in.IDs {
							if id <= 0 {
								return auth.Request{}, errors.NewCode(errors.InvalidInput, "group ID must be positive")
							}
							ids = append(ids, strconv.FormatInt(id, 10))
						}
						return auth.Request{IDs: ids}, nil
					}}
				if resource.name == "tenant_scope" || resource.name == "root_scope" {
					binding.When = func(ctx context.Context, _ groupWriteInput, _ []*app.CommandGrant) (bool, error) {
						return svc.ManagedScopeIDFromContext(ctx) <= 0, nil
					}
					binding.ConditionPath = "trusted missing managed scope -> bound tenant key/root ID -> actual tenant/scope repositories with independent specs"
				}
				executor.resources[action] = append(executor.resources[action], binding)
			}
			// Validate the same resource template used by every invocation.
			command, err := executor.command(action, nil)
			if err != nil {
				return err
			}
			if _, err := command.AuthorizationBinding(); err != nil {
				return err
			}
		}
		if http {
			s.httpWriteApplication = executor
		} else {
			s.writeApplication = executor
		}
	}
	return nil
}

func (a *groupWriteApplication) command(action string, invoke func(context.Context, *appcrud.Application[*iamentity.Group, int64], *groupWriteAccess) (*iamentity.Group, error)) (*app.Command[groupWriteInput, *groupWriteAccess, *iamentity.Group], error) {
	return newGroupWriteCommand(a, action, invoke)
}

func newGroupWriteCommand[Output any](a *groupWriteApplication, action string, invoke func(context.Context, *appcrud.Application[*iamentity.Group, int64], *groupWriteAccess) (Output, error)) (*app.Command[groupWriteInput, *groupWriteAccess, Output], error) {
	return app.NewCommand(app.CommandOptions[groupWriteInput, *groupWriteAccess, Output]{Resources: a.resources[action],
		Access: func(_ context.Context, in groupWriteInput, grants []*app.CommandGrant) (*groupWriteAccess, error) {
			return a.bindWriteAccess(action, in, grants)
		}, Handler: func(ctx context.Context, _ groupWriteInput, access *groupWriteAccess) (Output, error) {
			var zero Output
			if invoke == nil {
				return zero, errors.NewCode(errors.InvalidInput, "group write invocation is required")
			}
			options := a.options
			options.CommandGrant = access.primary
			options.Hooks = a.writeHooks(access)
			var repository appcrud.Repository[*iamentity.Group, int64] = a.service.groupRepo.Repo
			if action == appcrud.ActionDelete {
				repository = a.service.groupRepo
			}
			core, err := appcrud.NewApplication(repository, options)
			if err != nil {
				return zero, err
			}
			result, err := invoke(ctx, core, access)
			switch output := any(result).(type) {
			case *iamentity.Group:
				if output != nil {
					output.Parent = access.parents[output.GetID()]
				}
			case []*iamentity.Group:
				for _, item := range output {
					if item != nil {
						item.Parent = access.parents[item.GetID()]
					}
				}
			}
			return result, err
		}})
}

func (a *groupWriteApplication) bindWriteAccess(action string, in groupWriteInput, grants []*app.CommandGrant) (*groupWriteAccess, error) {
	access := &groupWriteAccess{before: map[int64]*iamentity.Group{}, known: map[int64]bool{}, staged: map[int64][]*iamentity.Group{}, parents: map[int64]*iamentity.Group{}}
	for _, id := range in.IDs {
		access.known[id] = true
	}
	if len(grants) != len(a.resources[action]) || len(grants) < 2 {
		return nil, errors.NewCode(errors.InvalidInput, "group write requires every declared resource")
	}
	for i, resource := range a.resources[action] {
		if grants[i] == nil && resource.When != nil {
			continue
		}
		if grants[i] == nil || grants[i].Name() != resource.Name {
			return nil, errors.NewCode(errors.InvalidInput, "group write grant differs from its declaration")
		}
	}
	access.primary = grants[0]
	var err error
	if action == appcrud.ActionDelete {
		access.childrenExists, err = app.NewCommandReader(a.service.groupRepo.Repo, grants[1], func(ctx context.Context, id int64, condition spec.Spec) (bool, error) {
			if !access.known[id] {
				return false, errors.NewCode(errors.Forbidden, "group deletion target differs from its intent")
			}
			count, err := a.service.groupRepo.Repo.QueryCount(ctx, query.QueryOptions{}, spec.And(condition, spec.Eq(meta.ByField("ParentID"), id)))
			return count > 0, err
		})
		if err != nil {
			return nil, err
		}
		access.membersExists, err = app.NewCommandReader(a.service.userRepo.Repo, grants[2], func(ctx context.Context, id int64, condition spec.Spec) (bool, error) {
			if !access.known[id] {
				return false, errors.NewCode(errors.Forbidden, "group deletion target differs from its intent")
			}
			counts, err := a.service.userRepo.GroupMemberCounts(ctx, []int64{id}, condition)
			return counts[id] > 0, err
		})
		return access, err
	}
	access.directory, err = app.NewCommandReader(a.service.groupRepo.Repo, grants[1], func(ctx context.Context, lookup groupDirectoryQuery, condition spec.Spec) ([]*iamentity.Group, error) {
		switch lookup.Operation {
		case "parent":
			if lookup.ID <= 0 {
				return nil, errors.NewCode(errors.InvalidInput, "parent group ID must be positive")
			}
			item, err := a.service.groupRepo.Repo.Get(ctx, lookup.ID, condition)
			if err != nil {
				return nil, errors.Wrap(err, errors.NotFound, "父组织不存在")
			}
			return []*iamentity.Group{item}, nil
		default:
			return nil, errors.NewCode(errors.InvalidInput, "group directory operation is not declared")
		}
	})
	if err != nil {
		return nil, err
	}
	access.duplicates, err = app.NewCommandReader(a.service.groupRepo.Repo, grants[2], func(ctx context.Context, lookup groupDirectoryQuery, condition spec.Spec) (bool, error) {
		if lookup.Operation != "duplicate" || !access.known[lookup.ID] {
			return false, errors.NewCode(errors.Forbidden, "name directory target differs from the write intent")
		}
		condition = spec.And(condition, spec.Eq(meta.ByField("Name"), lookup.Name))
		if lookup.ParentID == nil {
			condition = spec.And(condition, spec.IsNull(meta.ByField("ParentID")))
		} else {
			condition = spec.And(condition, spec.Eq(meta.ByField("ParentID"), *lookup.ParentID))
		}
		catalog, err := a.service.groupRepo.Repo.ScopedQueryWithSpec(ctx, condition)
		if err != nil {
			return false, err
		}
		count, err := catalog.Where("groups.id <> ?", lookup.ID).Count()
		return count > 0, err
	})
	if err != nil {
		return nil, err
	}
	if action == appcrud.ActionUpdate {
		access.links, err = app.NewCommandReader(a.service.groupRepo.Repo, grants[3], func(ctx context.Context, parentID int64, condition spec.Spec) ([]int64, error) {
			if !access.known[parentID] {
				return nil, errors.NewCode(errors.Forbidden, "subtree source is outside the authorized traversal")
			}
			var ids []int64
			for offset := 0; ; offset += 1000 {
				items, err := a.service.groupRepo.Repo.Query(ctx, query.QueryOptions{Fields: []string{"ID", "ParentID"}, Offset: offset, Limit: 1000, Sorts: []query.Sort{{Field: "id", Direction: query.ASC}}},
					spec.And(condition, spec.Eq(meta.ByField("ParentID"), parentID)))
				if err != nil {
					return nil, err
				}
				for _, item := range items {
					ids = append(ids, item.GetID())
				}
				if len(items) < 1000 {
					return ids, nil
				}
			}
		})
		if err != nil {
			return nil, err
		}
		access.subtree, err = app.NewCommandRepository(a.service.groupRepo.Repo, grants[4])
	} else if len(grants) == 5 && grants[3] != nil && grants[4] != nil {
		access.scope, err = a.service.scopeAuthorizer.BindTenantScopeReader(grants[3], grants[4])
	}
	return access, err
}

func (a *groupWriteApplication) writeHooks(access *groupWriteAccess) appcrud.Hooks[*iamentity.Group] {
	return appcrud.Hooks[*iamentity.Group]{
		appcrud.ActionCreate: {Before: func(ctx context.Context, item *iamentity.Group) error {
			tenantID, err := svc.TenantIDFromContext(ctx)
			if err != nil {
				return err
			}
			item.TenantID, item.ManagedScopeID, item.OwnerID = tenantID, svc.ManagedScopeIDFromContext(ctx), svc.TenantOwnerID(tenantID)
			if item.ManagedScopeID <= 0 && access.scope != nil {
				root, err := access.scope.Read(ctx)
				if err != nil {
					return err
				}
				item.ManagedScopeID = root.GetID()
			}
			if item.ManagedScopeID <= 0 {
				return errors.NewCode(errors.InvalidInput, "managed scope is required")
			}
			if err := a.service.groupRepo.Repo.EnsureID(item); err != nil {
				return err
			}
			access.known[item.GetID()] = true
			return prepareGroupWrite(ctx, item, nil, access)
		}},
		appcrud.ActionUpdate: {Before: func(ctx context.Context, item *iamentity.Group) error {
			current := access.before[item.ID]
			if current == nil {
				return errors.NewCode(errors.FailedPrecondition, "group update requires its transaction snapshot")
			}
			return prepareGroupWrite(ctx, item, current, access)
		}, After: func(ctx context.Context, item *iamentity.Group) error {
			item.Parent = access.parents[item.GetID()]
			parents := map[int64]*iamentity.Group{item.GetID(): item}
			for _, child := range access.staged[item.GetID()] {
				if child.ParentID == nil || parents[*child.ParentID] == nil {
					return errors.NewCode(errors.Concurrency, "subtree relationship changed during the group update")
				}
				child.SetParent(parents[*child.ParentID])
				if err := access.subtree.Update(ctx, child); err != nil {
					return err
				}
				parents[child.GetID()] = child
			}
			return nil
		}},
		appcrud.ActionDelete: {Before: func(ctx context.Context, item *iamentity.Group) error {
			children, err := access.childrenExists.Read(ctx, item.GetID())
			if err != nil {
				return err
			}
			if children {
				return errors.NewCode(errors.Validation, "不能删除有子组织的组织，请先处理子组织")
			}
			members, err := access.membersExists.Read(ctx, item.GetID())
			if err != nil {
				return err
			}
			if members {
				return errors.NewCode(errors.Validation, "不能删除有用户的组织，请先移除用户")
			}
			return nil
		}},
	}
}

func prepareGroupWrite(ctx context.Context, item, current *iamentity.Group, access *groupWriteAccess) error {
	changed := current != nil && !sameParentID(current.ParentID, item.ParentID)
	if current != nil && item.ParentID != nil && *item.ParentID == current.GetID() {
		return errors.NewCode(errors.Validation, "不能将组织设置为自己的父组织")
	}
	var parent *iamentity.Group
	if item.ParentID != nil {
		items, err := access.directory.Read(ctx, groupDirectoryQuery{Operation: "parent", ID: *item.ParentID})
		if err != nil {
			return err
		}
		parent = items[0]
	}
	var descendants []*iamentity.Group
	maxDepth := 0
	if changed {
		queue := []*iamentity.Group{current}
		seen := map[int64]bool{current.GetID(): true}
		for index := 0; index < len(queue); index++ {
			source := queue[index]
			ids, err := access.links.Read(ctx, source.GetID())
			if err != nil {
				return err
			}
			for _, id := range ids {
				if seen[id] {
					return errors.NewCode(errors.Validation, "组织层级包含循环关系")
				}
				seen[id] = true
				child, err := access.subtree.Get(ctx, id)
				if err != nil {
					return err
				}
				if child.ParentID == nil || *child.ParentID != source.GetID() {
					return errors.NewCode(errors.Concurrency, "subtree relationship changed during the group update")
				}
				access.known[id] = true
				maxDepth = max(maxDepth, child.Level-current.Level)
				descendants, queue = append(descendants, child), append(queue, child)
			}
		}
		if parent != nil && seen[parent.GetID()] {
			return errors.NewCode(errors.Validation, "不能将组织移动到其子组织下")
		}
	}
	level := 1
	if parent != nil {
		level = parent.Level + 1
	}
	if level+maxDepth > svc.MaxGroupLevel {
		return errors.NewCode(errors.Validation, "组织层级不能超过10级")
	}
	if current == nil || changed || current.Name != item.Name {
		duplicates, err := access.duplicates.Read(ctx, groupDirectoryQuery{Operation: "duplicate", ID: item.GetID(), Name: item.Name, ParentID: item.ParentID})
		if err != nil {
			return err
		}
		if duplicates {
			return errors.NewCode(errors.Validation, "同一层级下组织名称不能重复")
		}
	}
	item.SetParent(parent)
	item.Children, item.Users, item.DefaultRoles = nil, nil, nil
	// Persist only the aggregate; related records have their own entry capabilities.
	item.Parent = nil
	access.parents[item.GetID()] = parent
	access.staged[item.GetID()] = descendants
	return nil
}

func (a *groupWriteApplication) execute(ctx context.Context, action string, ids []int64, invoke func(context.Context, *appcrud.Application[*iamentity.Group, int64], *groupWriteAccess) (*iamentity.Group, error)) (*iamentity.Group, error) {
	command, err := a.command(action, invoke)
	if err != nil {
		return nil, errors.Wrap(err, errors.InvalidInput, "group write action is not declared: "+strings.TrimSpace(action))
	}
	return command.Execute(ctx, groupWriteInput{IDs: ids})
}
