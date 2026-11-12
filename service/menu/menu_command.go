package menu

import (
	"context"
	"strconv"
	"strings"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	svc "gochen-iam/service"
	"gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	appcrud "gochen/app/crud"
	"gochen/auth"
	"gochen/domain/spec"
	"gochen/errors"
	"gochen/httpx"
)

type menuActionInput struct {
	ID        int64
	Published bool
	Sync      *SyncMenuItemsRequest
}
type menuActionResult struct {
	Item  *iamentity.MenuItem
	Items []*iamentity.MenuItem
	Sync  *SyncMenuItemsResult
	Tree  []*MenuNode
}
type menuLookupInput struct {
	Operation, Code, ParentCode string
	Item                        *iamentity.MenuItem
	Definitions                 map[string]SyncMenuItemRequest
	Staged                      map[string]*iamentity.MenuItem
}
type menuLookupResult struct {
	Item     *iamentity.MenuItem
	ParentID *int64
	Items    []*iamentity.MenuItem
}
type menuActionAccess struct {
	menus, creates *app.CommandRepository[*iamentity.MenuItem, int64]
	lookup         *app.CommandReader[menuLookupInput, menuLookupResult]
}
type menuActionCommand = app.Command[menuActionInput, menuActionAccess, menuActionResult]

// HTTP constraints preserve the existing authenticated management boundary.
type menuEntryPolicy struct{ management bool }

func (menuEntryPolicy) Vocabulary() auth.Vocabulary { return auth.Vocabulary{} }
func (p menuEntryPolicy) Evaluate(ctx context.Context, _ auth.Request) (auth.Decision, error) {
	principal, err := hostauthz.RequirePrincipal(ctx)
	if err != nil {
		return auth.Decision{}, err
	}
	id, _ := strconv.ParseInt(principal.SubjectID, 10, 64)
	if id <= 0 {
		return auth.Decision{}, errors.NewCode(errors.Unauthorized, "用户未认证")
	}
	if p.management {
		if !tenant.CurrentContext(ctx).IsSingle() && iamauth.ActiveScopeKindFromContext(ctx) != string(iamperm.ScopePlatform) {
			return auth.Decision{}, errors.NewCode(errors.Forbidden, "当前授权域不允许访问此权限")
		}
		if !principal.AllowsPermission(iamperm.ApiPermission(iamperm.ResourceMenu, iamperm.ActionManage).Code) {
			return auth.Decision{}, errors.NewCode(errors.Forbidden, "权限不足")
		}
	}
	return auth.Decision{Allowed: true, Spec: spec.All()}, nil
}
func (s *MenuService) compileExecutions() error {
	if s.menuRepo == nil || s.menuRepo.Repo == nil || s.authorizer == nil {
		return errors.NewCode(errors.InvalidInput, "menu service requires its actual repository and IAM declarations")
	}
	for _, http := range []bool{false, true} {
		options := appcrud.Options[*iamentity.MenuItem, int64]{Resource: "menu", ActionPermissions: map[string]string{
			appcrud.ActionRead: svc.MenuPermissionSet.Code(iamperm.ActionRead), appcrud.ActionList: svc.MenuPermissionSet.Code(iamperm.ActionRead),
			appcrud.ActionCreate: svc.MenuPermissionSet.Code(iamperm.ActionWrite), appcrud.ActionUpdate: svc.MenuPermissionSet.Code(iamperm.ActionWrite), appcrud.ActionDelete: svc.MenuPermissionSet.Code(iamperm.ActionWrite),
		}, Hooks: s.crudHooks()}
		descriptor, err := appcrud.Describe(options, true)
		if err != nil {
			return err
		}
		var constraints []auth.IPolicy
		if http {
			constraints = []auth.IPolicy{menuEntryPolicy{management: true}}
		}
		options.Authorizer, err = s.authorizer.Compile(descriptor, s.menuRepo.ExecutionDescriptor().Metadata(), constraints...)
		if err != nil {
			return err
		}
		application, err := appcrud.NewApplication(s.menuRepo, options)
		if err != nil {
			return err
		}
		if http {
			s.httpApplication = application
		} else {
			s.application = application
		}
	}
	s.commands = map[string]*menuActionCommand{}
	for _, action := range []string{"list_all", "publish", "restore", "purge", "sync", "my", "http_publish", "http_restore", "http_purge", "http_sync", "http_my"} {
		command, err := s.compileCommand(action)
		if err != nil {
			return err
		}
		s.commands[action] = command
	}
	return nil
}
func (s *MenuService) compileCommand(action string) (*menuActionCommand, error) {
	base := strings.TrimPrefix(action, "http_")
	kind, permission := auth.KindUpdate, svc.MenuPermissionSet.Code(iamperm.ActionWrite)
	if base == "publish" {
		permission = svc.MenuPermissionSet.Code(iamperm.ActionPublish)
	}
	if base == "purge" {
		kind = auth.KindDelete
	}
	if base == "my" {
		kind, permission = auth.KindRead, ""
	}
	if base == "list_all" {
		kind, permission = auth.KindList, svc.MenuPermissionSet.Code(iamperm.ActionRead)
	}
	var constraints []auth.IPolicy
	if strings.HasPrefix(action, "http_") {
		constraints = []auth.IPolicy{menuEntryPolicy{management: base != "my"}}
	}
	compile := func(name string, resourceKind auth.Kind) (*auth.Authorizer, error) {
		descriptor := auth.Descriptor{Resource: svc.MenuResourceKind, Actions: []auth.Action{{Name: name, Kind: resourceKind, Permission: permission}}}
		if base == "my" {
			return auth.Compile(auth.Declaration{Descriptor: descriptor, ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{ID: "iam.menu.navigation", AllowReason: "published navigation has no action permission; the bound reader requires a trusted numeric user and filters their permissions"}}}, auth.CompileOptions{Metadata: s.menuRepo.ExecutionDescriptor().Metadata()})
		}
		return s.authorizer.Compile(descriptor, s.menuRepo.ExecutionDescriptor().Metadata(), constraints...)
	}
	authorizer, err := compile(action, kind)
	if err != nil {
		return nil, err
	}
	resources := []app.CommandResource[menuActionInput]{{Name: "menu", Repository: s.menuRepo, Authorizer: authorizer, Action: action, ConditionPath: "CommandRepository -> MenuRepository(spec, version, soft deletion); navigation CommandReader -> complete published global catalog", Intent: func(in menuActionInput) (auth.Request, error) {
		if base == "sync" || base == "my" || base == "list_all" {
			return auth.Request{}, nil
		}
		if in.ID <= 0 {
			return auth.Request{}, errors.NewCode(errors.InvalidInput, "menu ID must be positive")
		}
		return auth.Request{IDs: []string{strconv.FormatInt(in.ID, 10)}}, nil
	}}}
	if base == "list_all" {
		resources[0].ConditionPath = "CommandReader -> complete authorized global menu catalog -> ListAll(deleted_at IS NULL)"
	}
	if base == "sync" {
		creates, err := compile(action+"_creates", auth.KindCreate)
		if err != nil {
			return nil, err
		}
		resources = append(resources, app.CommandResource[menuActionInput]{Name: "menu_creates", Repository: s.menuRepo, Authorizer: creates, Action: action + "_creates", Intent: func(menuActionInput) (auth.Request, error) { return auth.Request{}, nil }})
	}
	if base == "publish" || base == "sync" {
		lookup, err := compile(action+"_relations", auth.KindRead)
		if err != nil {
			return nil, err
		}
		resources = append(resources, app.CommandResource[menuActionInput]{Name: "menu_relations", Repository: s.menuRepo, Authorizer: lookup, Action: action + "_relations", ConditionPath: "CommandReader -> full authorized global menu catalog -> code uniqueness and parent-chain validation", Intent: func(menuActionInput) (auth.Request, error) { return auth.Request{}, nil }})
	}
	return app.NewCommand(app.CommandOptions[menuActionInput, menuActionAccess, menuActionResult]{Resources: resources, Access: func(_ context.Context, _ menuActionInput, grants []*app.CommandGrant) (menuActionAccess, error) {
		return s.bindMenuAccess(action, grants)
	}, Handler: func(ctx context.Context, in menuActionInput, access menuActionAccess) (menuActionResult, error) {
		if access.lookup != nil {
			if _, err := access.lookup.Read(ctx, menuLookupInput{Operation: "check"}); err != nil {
				return menuActionResult{}, err
			}
		}
		if base == "my" {
			out, err := access.lookup.Read(ctx, menuLookupInput{Operation: "published"})
			if err != nil {
				return menuActionResult{}, err
			}
			request, err := httpx.NewRequestContext(ctx)
			if err != nil {
				return menuActionResult{}, err
			}
			return menuActionResult{Tree: buildMenuTree(out.Items, request)}, nil
		}
		if base == "list_all" {
			out, err := access.lookup.Read(ctx, menuLookupInput{Operation: "all"})
			return menuActionResult{Items: out.Items}, err
		}
		var result menuActionResult
		err := s.menuRepo.WithinTx(ctx, func(txCtx context.Context) error {
			if base == "sync" {
				var err error
				result.Sync, err = s.syncMenuItems(txCtx, in.Sync, access)
				return err
			}
			if base == "publish" {
				item, err := access.menus.Get(txCtx, in.ID)
				if err != nil {
					return err
				}
				item.Published = in.Published
				validated, err := access.lookup.Read(txCtx, menuLookupInput{Operation: "validate_update", Item: item})
				if err != nil {
					return err
				}
				result.Item = validated.Item
				return access.menus.Update(txCtx, result.Item)
			}
			item, err := access.menus.GetWithDeleted(txCtx, in.ID)
			if err != nil {
				return err
			}
			result.Item = item
			if base == "restore" {
				if item.DeletedAt == nil {
					return nil
				}
				return access.menus.Restore(txCtx, item)
			}
			return access.menus.Purge(txCtx, item)
		})
		return result, err
	}})
}
func (s *MenuService) bindMenuAccess(action string, grants []*app.CommandGrant) (menuActionAccess, error) {
	base := strings.TrimPrefix(action, "http_")
	names := []string{"menu"}
	if base == "sync" {
		names = append(names, "menu_creates")
	}
	if base == "sync" || base == "publish" {
		names = append(names, "menu_relations")
	}
	if len(grants) != len(names) {
		return menuActionAccess{}, errors.NewCode(errors.InvalidInput, "menu capabilities require every resource grant")
	}
	for i, name := range names {
		if grants[i] == nil || grants[i].Name() != name {
			return menuActionAccess{}, errors.NewCode(errors.InvalidInput, "menu capability resource differs from its declaration")
		}
		req, err := grants[i].Request()
		if err != nil {
			return menuActionAccess{}, err
		}
		expected := action
		if name == "menu_creates" {
			expected += "_creates"
		}
		if name == "menu_relations" {
			expected += "_relations"
		}
		if req.Resource != svc.MenuResourceKind || req.Action != expected {
			return menuActionAccess{}, errors.NewCode(errors.InvalidInput, "menu capability action differs from its declaration")
		}
	}
	var access menuActionAccess
	var err error
	if base != "my" && base != "list_all" {
		access.menus, err = app.NewCommandRepository(s.menuRepo, grants[0])
		if err != nil {
			return access, err
		}
	}
	if base == "sync" {
		access.creates, err = app.NewCommandRepository(s.menuRepo, grants[1])
		if err != nil {
			return access, err
		}
	}
	if base == "my" || base == "list_all" || base == "sync" || base == "publish" {
		grant := grants[len(grants)-1]
		access.lookup, err = app.NewCommandReader(s.menuRepo, grant, func(ctx context.Context, in menuLookupInput, condition spec.Spec) (menuLookupResult, error) {
			allowed := in.Operation == "check"
			switch base {
			case "my":
				allowed = allowed || in.Operation == "published"
			case "list_all":
				allowed = allowed || in.Operation == "all"
			case "publish":
				allowed = allowed || in.Operation == "validate_update"
			case "sync":
				allowed = allowed || in.Operation == "code_deleted" || in.Operation == "validate_create" || in.Operation == "validate_update" || in.Operation == "validate_sync" || in.Operation == "resolve_sync"
			}
			if !allowed {
				return menuLookupResult{}, errors.NewCode(errors.Forbidden, "menu projection operation is outside this command")
			}
			if base == "my" {
				if _, err := (menuEntryPolicy{}).Evaluate(ctx, auth.Request{}); err != nil {
					return menuLookupResult{}, err
				}
			}
			if !condition.IsAll() {
				return menuLookupResult{}, errors.NewCode(errors.Forbidden, "menu projections require the complete authorized global catalog")
			}
			var out menuLookupResult
			var err error
			switch in.Operation {
			case "check":
			case "published":
				out.Items, err = s.menuRepo.ListPublished(ctx)
			case "all":
				out.Items, err = s.menuRepo.ListAll(ctx)
			case "code_deleted":
				out.Item, err = s.menuRepo.FindByCodeWithDeleted(ctx, in.Code)
			case "validate_create":
				out.Item = in.Item
				err = s.validateMenuForCreate(ctx, out.Item)
			case "validate_update":
				out.Item = in.Item
				err = s.validateMenuForUpdate(ctx, out.Item, condition)
			case "validate_sync":
				err = s.validateSyncMenuParentCodes(ctx, in.Definitions)
			case "resolve_sync":
				out.ParentID, err = s.resolveSyncMenuParentID(ctx, in.ParentCode, in.Staged)
			default:
				err = errors.NewCode(errors.InvalidInput, "unknown menu projection operation")
			}
			return out, err
		})
	}
	return access, err
}
func (s *MenuService) execute(ctx context.Context, action string, in menuActionInput) (menuActionResult, error) {
	command := s.commands[action]
	if command == nil {
		return menuActionResult{}, errors.NewCode(errors.InvalidInput, "menu action is not declared")
	}
	return command.Execute(ctx, in)
}
func (s *MenuService) AuthorizationBinding(action string) (auth.EntryBinding, error) {
	if command := s.commands["http_"+action]; command != nil {
		return command.AuthorizationBinding()
	}
	if s.httpApplication == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "menu HTTP application is not declared")
	}
	return s.httpApplication.AuthorizationBinding(action)
}
func (s *MenuService) HTTPApplication() *appcrud.Application[*iamentity.MenuItem, int64] {
	return s.httpApplication
}
func (s *MenuService) SyncMenuItems(ctx context.Context, req *SyncMenuItemsRequest) (*SyncMenuItemsResult, error) {
	out, err := s.execute(ctx, "sync", menuActionInput{Sync: req})
	return out.Sync, err
}
func (s *MenuService) SyncMenuItemsHTTP(ctx context.Context, req *SyncMenuItemsRequest) (*SyncMenuItemsResult, error) {
	out, err := s.execute(ctx, "http_sync", menuActionInput{Sync: req})
	return out.Sync, err
}
func (s *MenuService) MenuActionHTTP(ctx context.Context, action string, id int64, published bool) (*iamentity.MenuItem, error) {
	out, err := s.execute(ctx, "http_"+action, menuActionInput{ID: id, Published: published})
	return out.Item, err
}
func (s *MenuService) MyMenuTree(ctx context.Context) ([]*MenuNode, error) {
	out, err := s.execute(ctx, "my", menuActionInput{})
	return out.Tree, err
}
func (s *MenuService) MyMenuTreeHTTP(ctx context.Context) ([]*MenuNode, error) {
	out, err := s.execute(ctx, "http_my", menuActionInput{})
	return out.Tree, err
}
