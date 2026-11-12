package role

import (
	"context"
	"strconv"
	"strings"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	svc "gochen-iam/service"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	appcrud "gochen/app/crud"
	"gochen/auth"
	"gochen/domain/crud"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

type roleCRUDInput struct {
	IDs  []int64
	Name string
}
type roleNameQuery struct {
	ID   int64
	Name string
}
type roleCRUDAccess struct {
	known         map[int64]bool
	namespaceIDs  map[int64]bool
	primary       *app.CommandGrant
	before        map[int64]*iamentity.Role
	names         *app.CommandReader[roleNameQuery, bool]
	users, groups *app.CommandReader[int64, int64]
	namespace     *app.CommandReader[int64, *iamentity.Scope]
	root          *svc.TenantScopeReader
	source        *app.CommandRepository[*iamentity.Role, int64]
}

// roleCRUDApplication 为每次调用绑定私有治理能力，Core 负责事务、版本和生命周期。
type roleCRUDApplication struct {
	*appcrud.Application[*iamentity.Role, int64]
	service   *RoleService
	options   appcrud.Options[*iamentity.Role, int64]
	resources map[string][]app.CommandResource[roleCRUDInput]
}

func (s *RoleService) compileCRUDApplications() error {
	for _, http := range []bool{false, true} {
		options := appcrud.Options[*iamentity.Role, int64]{Resource: "role", ActionPermissions: map[string]string{
			"read": "role:api:read", "list": "role:api:read", "create": "role:api:write", "update": "role:api:write", "delete": "role:api:delete",
		}}
		descriptor, err := appcrud.Describe(options, true)
		if err != nil {
			return err
		}
		var guards []auth.IPolicy
		if http {
			guards = []auth.IPolicy{roleHTTPEntryPolicy{}}
		}
		options.Authorizer, err = s.authorizer.Compile(descriptor, s.roleRepo.ExecutionDescriptor().Metadata(), guards...)
		if err != nil {
			return err
		}
		core, err := appcrud.NewApplication(s.roleRepo.Repo, options)
		if err != nil {
			return err
		}
		a := &roleCRUDApplication{Application: core, service: s, options: options, resources: map[string][]app.CommandResource[roleCRUDInput]{}}
		for _, action := range []string{"create", "update", "delete"} {
			provider := app.IExecutionDescriptorProvider(s.roleRepo.Repo)
			if action == "delete" {
				provider = s.roleRepo
			}
			a.resources[action] = []app.CommandResource[roleCRUDInput]{{Name: "role", Repository: provider, Authorizer: options.Authorizer.(*auth.Authorizer), Action: action,
				ConditionPath: "Core CRUD -> private role governance -> same transaction, protected fields and conditional version write",
				Intent: func(in roleCRUDInput) (auth.Request, error) {
					if action == "create" {
						return auth.Request{}, nil
					}
					ids := make([]string, 0, len(in.IDs))
					for _, id := range in.IDs {
						if id <= 0 {
							return auth.Request{}, errors.NewCode(errors.InvalidInput, "role ID must be positive")
						}
						ids = append(ids, strconv.FormatInt(id, 10))
					}
					return auth.Request{IDs: ids}, nil
				}}}
			type dependency struct {
				name, resource string
				provider       app.IExecutionDescriptorProvider
			}
			deps := []dependency{}
			if action == "delete" {
				deps = append(deps, dependency{"user_references", "iam.role.user_references", s.userRepo}, dependency{"group_references", "iam.role.group_references", s.roleRepo})
			} else {
				deps = append(deps, dependency{"names", "iam.role.name_directory", s.roleRepo.Repo})
				if s.scopeAuthorizer != nil {
					tenants, scopes, err := s.scopeAuthorizer.TenantScopeProviders()
					if err != nil {
						return err
					}
					if action == "create" {
						deps = append(deps, dependency{"tenant", "iam.role.tenant", tenants}, dependency{"root", "iam.role.root", scopes})
					} else {
						deps = append(deps, dependency{"namespace", "iam.role.namespace", scopes})
						deps = append(deps, dependency{"tenant", "iam.role.tenant", tenants}, dependency{"root", "iam.role.root", scopes})
					}
				}
			}
			for _, dep := range deps {
				permission := svc.RolePermissionSet.Code(iamperm.ActionWrite)
				if action == "delete" {
					permission = svc.RolePermissionSet.Code(iamperm.ActionDelete)
				}
				d := auth.Descriptor{Resource: dep.resource, Actions: []auth.Action{{Name: action + "_" + dep.name, Kind: auth.KindRead, Permission: permission}}}
				// 完整性投影按已授权角色派生；检查完整引用集合，保持租户内唯一性和删除约束。
				authorizer, err := auth.Compile(auth.Declaration{Descriptor: d, ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{ID: dep.resource, System: auth.SystemCheckConstraints, UnauthorizedAsDenial: true, Constraints: guards}}}, auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: dep.provider.ExecutionDescriptor().Metadata()})
				if err != nil {
					return err
				}
				a.resources[action] = append(a.resources[action], app.CommandResource[roleCRUDInput]{Name: dep.name, Repository: dep.provider, Authorizer: authorizer, Action: action + "_" + dep.name,
					ConditionPath: "private hook -> CommandReader -> trusted tenant/role ID and complete invariant projection; no association preload",
					Intent:        func(roleCRUDInput) (auth.Request, error) { return auth.Request{}, nil }})
			}
			if _, err := a.command(action, nil); err != nil {
				return err
			}
		}
		if http {
			s.httpCRUDApplication = a
		} else {
			s.crudApplication = a
		}
		a.resources["clone"] = append([]app.CommandResource[roleCRUDInput](nil), a.resources["create"]...)
		sourceAuthorizer, err := s.authorizer.Compile(auth.Descriptor{Resource: svc.RoleResourceKind, Actions: []auth.Action{{Name: "clone_source", Kind: auth.KindRead, Permission: "role:api:write"}}}, s.roleRepo.ExecutionDescriptor().Metadata(), guards...)
		if err != nil {
			return err
		}
		a.resources["clone"] = append(a.resources["clone"], app.CommandResource[roleCRUDInput]{Name: "source", Repository: s.roleRepo.Repo, Authorizer: sourceAuthorizer, Action: "clone_source", ConditionPath: "CommandRepository.Get -> frozen authorized source -> governed creation with complete name and namespace readers", Intent: func(in roleCRUDInput) (auth.Request, error) {
			if len(in.IDs) != 1 || in.IDs[0] <= 0 {
				return auth.Request{}, errors.NewCode(errors.InvalidInput, "clone requires one source role")
			}
			return auth.Request{IDs: []string{strconv.FormatInt(in.IDs[0], 10)}}, nil
		}})
	}
	return nil
}

func (a *roleCRUDApplication) command(action string, invoke func(context.Context, *appcrud.Application[*iamentity.Role, int64], *roleCRUDAccess) (*iamentity.Role, error)) (*app.Command[roleCRUDInput, *roleCRUDAccess, *iamentity.Role], error) {
	return newRoleCRUDCommand(a, action, invoke)
}

func newRoleCRUDCommand[Output any](a *roleCRUDApplication, action string, invoke func(context.Context, *appcrud.Application[*iamentity.Role, int64], *roleCRUDAccess) (Output, error)) (*app.Command[roleCRUDInput, *roleCRUDAccess, Output], error) {
	return app.NewCommand(app.CommandOptions[roleCRUDInput, *roleCRUDAccess, Output]{Resources: a.resources[action], Access: func(_ context.Context, in roleCRUDInput, grants []*app.CommandGrant) (*roleCRUDAccess, error) {
		return a.bind(action, in, grants)
	},
		Handler: func(ctx context.Context, _ roleCRUDInput, access *roleCRUDAccess) (Output, error) {
			var zero Output
			if invoke == nil {
				return zero, errors.NewCode(errors.InvalidInput, "role invocation is required")
			}
			options := a.options
			options.Hooks = a.hooks(access)
			options.CommandGrant = access.primary
			var repo appcrud.Repository[*iamentity.Role, int64] = a.service.roleRepo.Repo
			if action == "delete" {
				repo = a.service.roleRepo
			}
			core, err := appcrud.NewApplication(repo, options)
			if err != nil {
				return zero, err
			}
			return invoke(ctx, core, access)
		}})
}

func (a *roleCRUDApplication) bind(action string, in roleCRUDInput, grants []*app.CommandGrant) (*roleCRUDAccess, error) {
	access := &roleCRUDAccess{known: map[int64]bool{}, namespaceIDs: map[int64]bool{}, before: map[int64]*iamentity.Role{}}
	for _, id := range in.IDs {
		access.known[id] = true
	}
	if len(grants) != len(a.resources[action]) {
		return nil, errors.NewCode(errors.InvalidInput, "role resources are incomplete")
	}
	var tenantGrant, rootGrant *app.CommandGrant
	for i, resource := range a.resources[action] {
		g := grants[i]
		if g == nil || g.Name() != resource.Name {
			return nil, errors.NewCode(errors.InvalidInput, "role grant differs from declaration")
		}
		var err error
		switch resource.Name {
		case "role":
			access.primary = g
		case "names":
			access.names, err = app.NewCommandReader(a.service.roleRepo.Repo, g, func(ctx context.Context, in roleNameQuery, condition spec.Spec) (bool, error) {
				if !access.known[in.ID] || !condition.IsAll() {
					return false, errors.NewCode(errors.Forbidden, "role name target differs from intent")
				}
				tenant, err := svc.TenantIDFromContext(ctx)
				if err != nil {
					return false, err
				}
				catalog, err := a.service.roleRepo.Repo.ScopedQueryWithSpec(ctx, spec.And(condition, spec.Eq(meta.ByField("TenantID"), tenant), spec.Eq(meta.ByField("Name"), in.Name)))
				if err != nil {
					return false, err
				}
				count, err := catalog.Where("roles.id <> ?", in.ID).Count()
				return count > 0, err
			})
		case "source":
			access.source, err = app.NewCommandRepository(a.service.roleRepo.Repo, g)
		case "user_references", "group_references":
			reader, e := app.NewCommandReader(resource.Repository, g, func(ctx context.Context, id int64, condition spec.Spec) (int64, error) {
				if !access.known[id] || !condition.IsAll() {
					return 0, errors.NewCode(errors.Forbidden, "role reference target differs from intent")
				}
				if resource.Name == "user_references" {
					return a.service.userRepo.CountByRoleID(ctx, id)
				}
				return a.service.roleRepo.CountGroupsByRoleID(ctx, id)
			})
			err = e
			if resource.Name == "user_references" {
				access.users = reader
			} else {
				access.groups = reader
			}
		case "tenant":
			tenantGrant = g
		case "root":
			rootGrant = g
		case "namespace":
			access.namespace, err = app.NewCommandReader(resource.Repository, g, func(ctx context.Context, id int64, condition spec.Spec) (*iamentity.Scope, error) {
				if id <= 0 || !access.namespaceIDs[id] || !condition.IsAll() {
					return nil, errors.NewCode(errors.Forbidden, "namespace projection requires the trusted role namespace")
				}
				return a.service.scopeAuthorizer.Scope(ctx, id)
			})
		}
		if err != nil {
			return nil, err
		}
	}
	if tenantGrant != nil && rootGrant != nil {
		var err error
		access.root, err = a.service.scopeAuthorizer.BindTenantScopeReader(tenantGrant, rootGrant)
		if err != nil {
			return nil, err
		}
	}
	return access, nil
}

func (a *roleCRUDApplication) hooks(access *roleCRUDAccess) appcrud.Hooks[*iamentity.Role] {
	prepare := func(ctx context.Context, item, current *iamentity.Role) error {
		tenant, err := svc.TenantIDFromContext(ctx)
		if err != nil {
			return err
		}
		if current == nil {
			item.TenantID, item.OwnerID = tenant, svc.TenantOwnerID(tenant)
			item.Code, item.IsSystem, item.Status = item.Name, false, svc.RoleStatusActive
			item.NamespaceScopeID = svc.ManagedScopeIDFromContext(ctx)
		} else {
			if err := requireRoleOwnership(ctx, current); err != nil {
				return err
			}
			if current.IsSystem {
				return errors.NewCode(errors.Validation, "系统角色不能被修改")
			}
			item.TenantID, item.OwnerID, item.NamespaceScopeID = current.TenantID, current.OwnerID, current.NamespaceScopeID
			item.Code, item.IsSystem, item.Status = current.Code, current.IsSystem, current.Status
		}
		var namespace *iamentity.Scope
		if current == nil && access.root != nil {
			namespace, err = access.root.Read(ctx)
			if err == nil {
				item.NamespaceScopeID = namespace.ID
			}
		} else if current != nil && access.namespace != nil {
			access.namespaceIDs[current.NamespaceScopeID] = true
			namespace, err = access.namespace.Read(ctx, current.NamespaceScopeID)
			if errors.Is(err, errors.NotFound) && current.NamespaceScopeID > 0 && access.root != nil {
				namespace, err = access.root.Read(ctx)
			}
		} else {
			namespace = &iamentity.Scope{Entity: crud.Entity[int64]{ID: item.NamespaceScopeID}, Type: iamauth.ActiveScopeKindFromContext(ctx)}
		}
		if err != nil {
			return err
		}
		if namespace == nil || namespace.ID <= 0 || namespace.Type == "" {
			return errors.NewCode(errors.InvalidInput, "namespace scope boundary is required")
		}
		if err := validateRoleMutation(item, true); err != nil {
			return err
		}
		if err := validatePermissionsForScope([]string(item.Permissions), namespace); err != nil {
			return err
		}
		if err := a.service.roleRepo.Repo.EnsureID(item); err != nil {
			return err
		}
		access.known[item.ID] = true
		duplicate, err := access.names.Read(ctx, roleNameQuery{item.ID, item.Name})
		if err != nil {
			return err
		}
		if duplicate {
			return errors.NewCode(errors.Validation, "角色名称已存在")
		}
		item.NamespaceScope, item.Users, item.Groups = nil, nil, nil
		return nil
	}
	return appcrud.Hooks[*iamentity.Role]{
		"create": {Before: func(ctx context.Context, item *iamentity.Role) error { return prepare(ctx, item, nil) }},
		"update": {Before: func(ctx context.Context, item *iamentity.Role) error {
			current := access.before[item.ID]
			if current == nil {
				return errors.NewCode(errors.FailedPrecondition, "role update requires its transaction snapshot")
			}
			return prepare(ctx, item, current)
		}},
		"delete": {Before: func(ctx context.Context, item *iamentity.Role) error {
			if err := requireRoleOwnership(ctx, item); err != nil {
				return err
			}
			if item.IsSystem {
				return errors.NewCode(errors.Validation, "系统角色不能被删除")
			}
			if _, err := svc.RequireTenantMatch(ctx, item.TenantID); err != nil {
				return err
			}
			users, err := access.users.Read(ctx, item.ID)
			if err != nil {
				return err
			}
			if users > 0 {
				return errors.NewCode(errors.Validation, "角色正在被用户使用，不能删除")
			}
			groups, err := access.groups.Read(ctx, item.ID)
			if err != nil {
				return err
			}
			if groups > 0 {
				return errors.NewCode(errors.Validation, "角色正在被组织使用，不能删除")
			}
			return nil
		}},
	}
}

func requireRoleOwnership(ctx context.Context, item *iamentity.Role) error {
	principal, err := hostauthz.RequirePrincipal(ctx)
	if err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(item.OwnerID), string(iamperm.ScopePlatform)) && !principal.IsSystem && !strings.EqualFold(iamauth.ActiveScopeKindFromContext(ctx), string(iamperm.ScopePlatform)) {
		return errors.NewCode(errors.Forbidden, "平台自有角色只允许平台授权域访问")
	}
	_, err = svc.RequireTenantMatch(ctx, item.TenantID)
	return err
}

func (a *roleCRUDApplication) execute(ctx context.Context, action string, ids []int64, invoke func(context.Context, *appcrud.Application[*iamentity.Role, int64], *roleCRUDAccess) (*iamentity.Role, error)) (*iamentity.Role, error) {
	command, err := a.command(action, invoke)
	if err != nil {
		return nil, err
	}
	return command.Execute(ctx, roleCRUDInput{IDs: ids})
}

// HTTPApplication 返回普通服务与 HTTP 共用治理实现的声明式应用。
func (s *RoleService) HTTPApplication() appcrud.IApplication[*iamentity.Role, int64] {
	return s.httpCRUDApplication
}

func (a *roleCRUDApplication) AuthorizationBinding(action string) (auth.EntryBinding, error) {
	if action == "read" || action == "list" {
		return a.service.directoryCommands[a.directoryAction(action)].AuthorizationBinding()
	}
	if _, ok := a.resources[action]; !ok {
		return a.Application.AuthorizationBinding(action)
	}
	command, err := a.command(action, nil)
	if err != nil {
		return auth.EntryBinding{}, err
	}
	return command.AuthorizationBinding()
}
func (a *roleCRUDApplication) Create(ctx context.Context, item *iamentity.Role) error {
	if item == nil {
		return errors.NewCode(errors.InvalidInput, "role is required")
	}
	_, err := a.execute(ctx, "create", nil, func(ctx context.Context, core *appcrud.Application[*iamentity.Role, int64], access *roleCRUDAccess) (*iamentity.Role, error) {
		return item, core.Create(ctx, item)
	})
	return err
}
func (a *roleCRUDApplication) Update(ctx context.Context, item *iamentity.Role) error {
	if item == nil {
		return errors.NewCode(errors.InvalidInput, "role is required")
	}
	result, err := a.Execute(ctx, "update", item.ID, func(_ context.Context, current *iamentity.Role) error {
		if current.Version != item.Version {
			return errors.NewCode(errors.Concurrency, "role version has changed")
		}
		*current = *item
		return nil
	})
	if err == nil {
		*item = *result
	}
	return err
}
func (a *roleCRUDApplication) Delete(ctx context.Context, id int64) error {
	_, err := a.execute(ctx, "delete", []int64{id}, func(ctx context.Context, core *appcrud.Application[*iamentity.Role, int64], access *roleCRUDAccess) (*iamentity.Role, error) {
		return nil, core.Delete(ctx, id)
	})
	return err
}
func (a *roleCRUDApplication) DeleteBulk(ctx context.Context, ids []int64) error {
	_, err := a.execute(ctx, "delete", ids, func(ctx context.Context, core *appcrud.Application[*iamentity.Role, int64], access *roleCRUDAccess) (*iamentity.Role, error) {
		return nil, core.DeleteBulk(ctx, ids)
	})
	return err
}
