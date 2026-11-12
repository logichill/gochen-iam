package user

import (
	"context"
	"strconv"
	"strings"

	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	svc "gochen-iam/service"
	"gochen/app"
	appcrud "gochen/app/crud"
	"gochen/auth"
	domaudited "gochen/domain/audited"
	"gochen/errors"
)

type userHTTPExistingApplication struct {
	core      *appcrud.Application[*iamentity.User, int64]
	service   *UserService
	options   appcrud.Options[*iamentity.User, int64]
	resources map[string][]app.CommandResource[[]int64]
}

func (s *UserService) compileHTTPExisting() error {
	options := appcrud.Options[*iamentity.User, int64]{Resource: "user", ActionPermissions: map[string]string{
		appcrud.ActionRead: svc.UserPermissionSet.Code(iamperm.ActionRead), appcrud.ActionList: svc.UserPermissionSet.Code(iamperm.ActionRead),
		appcrud.ActionCreate: svc.UserPermissionSet.Code(iamperm.ActionWrite), appcrud.ActionUpdate: svc.UserPermissionSet.Code(iamperm.ActionWrite),
		appcrud.ActionDelete: svc.UserPermissionSet.Code(iamperm.ActionDelete),
	}}
	descriptor, err := appcrud.Describe(options, true)
	if err != nil {
		return err
	}
	primary, err := s.authorizer.Compile(descriptor, s.userRepo.ExecutionDescriptor().Metadata(), userAssociationEntryPolicy{})
	if err != nil {
		return err
	}
	options.Authorizer = primary
	options.Hooks = appcrud.Hooks[*iamentity.User]{appcrud.ActionCreate: {Before: s.prepareHTTPCreate}}
	core, err := appcrud.NewApplication(s.userRepo, options)
	if err != nil {
		return err
	}
	executor := &userHTTPExistingApplication{core: core, service: s, options: options, resources: map[string][]app.CommandResource[[]int64]{}}
	intent := func(ids []int64) (auth.Request, error) {
		keys := make([]string, 0, len(ids))
		for _, id := range ids {
			if id <= 0 {
				return auth.Request{}, errors.NewCode(errors.InvalidInput, "user ID must be positive")
			}
			keys = append(keys, strconv.FormatInt(id, 10))
		}
		return auth.Request{IDs: keys}, nil
	}
	for _, action := range []string{appcrud.ActionUpdate, appcrud.ActionDelete} {
		executor.resources[action] = []app.CommandResource[[]int64]{{Name: "user", Repository: s.userRepo, Authorizer: primary, Action: action, Intent: intent,
			ConditionPath: "Core CRUD -> actual UserRepo -> transaction, target/ownership/version condition and existing soft-delete behavior; every bulk target uses the same plan",
		}}
		command, err := newUserHTTPExistingCommand[*iamentity.User](executor, action, nil)
		if err != nil {
			return err
		}
		if _, err := command.AuthorizationBinding(); err != nil {
			return err
		}
	}
	s.httpExisting = executor
	return nil
}

func newUserHTTPExistingCommand[Output any](a *userHTTPExistingApplication, action string, invoke func(context.Context, *appcrud.Application[*iamentity.User, int64], *userHTTPExistingAccess) (Output, error)) (*app.Command[[]int64, *userHTTPExistingAccess, Output], error) {
	resources := a.resources[action]
	if len(resources) == 0 {
		return nil, errors.NewCode(errors.InvalidInput, "user HTTP write action is not declared")
	}
	return app.NewCommand(app.CommandOptions[[]int64, *userHTTPExistingAccess, Output]{Resources: resources,
		Access: func(_ context.Context, ids []int64, grants []*app.CommandGrant) (*userHTTPExistingAccess, error) {
			return a.bind(action, ids, grants)
		},
		Handler: func(ctx context.Context, _ []int64, access *userHTTPExistingAccess) (Output, error) {
			var zero Output
			if invoke == nil {
				return zero, errors.NewCode(errors.InvalidInput, "user HTTP write invocation is required")
			}
			return invoke(ctx, access.core, access)
		}})
}

func (a *userHTTPExistingApplication) bind(action string, ids []int64, grants []*app.CommandGrant) (*userHTTPExistingAccess, error) {
	resources := a.resources[action]
	if len(resources) == 0 || len(grants) != len(resources) {
		return nil, errors.NewCode(errors.InvalidInput, "user HTTP write requires every declared grant")
	}
	for i, resource := range resources {
		if grants[i] == nil || grants[i].Name() != resource.Name {
			return nil, errors.NewCode(errors.InvalidInput, "user HTTP write grant differs from its declaration")
		}
		request, err := grants[i].Request()
		if err != nil {
			return nil, err
		}
		plan, _ := resource.Authorizer.Plan()
		if request.Resource != plan.Descriptor.Resource || request.Action != resource.Action || len(request.IDs) != len(ids) {
			return nil, errors.NewCode(errors.InvalidInput, "user HTTP write action or targets differ from its declaration")
		}
		for index, id := range ids {
			if request.IDs[index] != strconv.FormatInt(id, 10) {
				return nil, errors.NewCode(errors.InvalidInput, "user HTTP write target differs from its intent")
			}
		}
	}
	access := &userHTTPExistingAccess{before: map[int64]*iamentity.User{}}
	options := a.options
	options.CommandGrant = grants[0]
	options.Hooks = appcrud.Hooks[*iamentity.User]{appcrud.ActionDelete: {Before: func(ctx context.Context, item *iamentity.User) error {
		tenantID, err := svc.TenantIDFromContext(ctx)
		if err != nil {
			return err
		}
		if item.TenantID != tenantID {
			return errors.NewCode(errors.Forbidden, "跨租户访问被拒绝")
		}
		return nil
	}}}
	if action == appcrud.ActionUpdate {
		options.Hooks[appcrud.ActionUpdate] = appcrud.Stage[*iamentity.User]{Before: func(ctx context.Context, item *iamentity.User) error {
			before := access.before[item.ID]
			if before == nil {
				return errors.NewCode(errors.FailedPrecondition, "user update requires its transaction snapshot")
			}
			return a.service.prepareHTTPUpdate(ctx, item, before)
		}}
	}
	var err error
	access.core, err = appcrud.NewApplication(a.service.userRepo, options)
	return access, err
}

func (s *UserService) prepareHTTPUpdate(ctx context.Context, item, current *iamentity.User) error {
	tenantID, err := svc.TenantIDFromContext(ctx)
	if err != nil {
		return err
	}
	if item.ID != current.ID || item.TenantID != current.TenantID || item.ManagedScopeID != current.ManagedScopeID || item.OwnerID != current.OwnerID {
		return errors.NewCode(errors.Forbidden, "user update snapshot ownership differs from its target")
	}
	if item.GetVersion() != current.GetVersion() {
		return errors.NewCode(errors.Concurrency, "user update snapshot version changed")
	}
	if item.TenantID != tenantID {
		return errors.NewCode(errors.Forbidden, "跨租户访问被拒绝")
	}
	if item.Password == "" {
		item.Password = current.Password
	} else if len(item.Password) != 60 || !(strings.HasPrefix(item.Password, "$2a$") || strings.HasPrefix(item.Password, "$2b$") || strings.HasPrefix(item.Password, "$2y$")) {
		if len(item.Password) < 6 {
			return errors.NewCode(errors.Validation, "密码长度不能少于6个字符")
		}
		if len(item.Password) > 72 {
			return errors.NewCode(errors.Validation, "密码长度不能超过72个字符")
		}
		item.Password, err = s.hashPassword(item.Password)
		if err != nil {
			return errors.Wrap(err, errors.Internal, "密码加密失败")
		}
	}
	if item.HomeTenantID == "" {
		item.HomeTenantID = tenantID
	}
	if item.HomeScopeID <= 0 {
		if scope := svc.ManagedScopeIDFromContext(ctx); scope > 0 {
			item.HomeScopeID = scope
		}
	}
	return nil
}

func (s *UserService) GetHTTP(ctx context.Context, id int64) (*iamentity.User, error) {
	return s.httpExisting.core.Get(ctx, id)
}

func (s *UserService) prepareHTTPCreate(ctx context.Context, item *iamentity.User) error {
	if len(item.Groups) != 0 || len(item.Roles) != 0 {
		return errors.NewCode(errors.Validation, "用户创建仅支持基础字段，组和角色请通过分配入口设置")
	}
	tenantID, err := svc.TenantIDFromContext(ctx)
	if err != nil {
		return err
	}
	scope := svc.ManagedScopeIDFromContext(ctx)
	if scope <= 0 {
		return errors.NewCode(errors.InvalidInput, "managed scope boundary is required")
	}
	item.TenantID, item.HomeTenantID = tenantID, tenantID
	item.ManagedScopeID, item.HomeScopeID = scope, scope
	item.OwnerID = svc.TenantOwnerID(tenantID)
	if item.Password != "" && (len(item.Password) != 60 || !(strings.HasPrefix(item.Password, "$2a$") || strings.HasPrefix(item.Password, "$2b$") || strings.HasPrefix(item.Password, "$2y$"))) {
		if len(item.Password) < 6 {
			return errors.NewCode(errors.Validation, "密码长度不能少于6个字符")
		}
		if len(item.Password) > 72 {
			return errors.NewCode(errors.Validation, "密码长度不能超过72个字符")
		}
		item.Password, err = s.hashPassword(item.Password)
		if err != nil {
			return errors.Wrap(err, errors.Internal, "密码加密失败")
		}
	}
	return nil
}

func (s *UserService) CreateHTTP(ctx context.Context, item *iamentity.User) error {
	return s.httpExisting.core.Create(ctx, item)
}

func (s *UserService) ExecuteNewHTTP(ctx context.Context, action string, fn func(context.Context) (*iamentity.User, error), options ...appcrud.ExecOption) (*iamentity.User, error) {
	if action != appcrud.ActionCreate {
		return nil, errors.NewCode(errors.InvalidInput, "user new execution requires the create action")
	}
	return s.httpExisting.core.ExecuteNew(ctx, action, fn, options...)
}

func (s *UserService) ExecuteNewBulkHTTP(ctx context.Context, action string, fn func(context.Context) ([]*iamentity.User, error), options ...appcrud.ExecOption) ([]*iamentity.User, error) {
	if action != appcrud.ActionCreate {
		return nil, errors.NewCode(errors.InvalidInput, "user new bulk execution requires the create action")
	}
	return s.httpExisting.core.ExecuteNewBulk(ctx, action, fn, options...)
}

func (s *UserService) HTTPDescriptor() auth.Descriptor { return s.httpExisting.core.Descriptor() }
func (s *UserService) HTTPMaxPageSize() int            { return s.httpExisting.core.MaxPageSize() }
func (s *UserService) HTTPMaxBulkSize() int            { return s.httpExisting.core.MaxBulkSize() }
func (s *UserService) AuditTrailHTTP(ctx context.Context, id int64, offset, limit int) ([]domaudited.AuditRecord, error) {
	return s.httpExisting.core.AuditTrail(ctx, id, offset, limit)
}

func (s *UserService) UpdateHTTP(ctx context.Context, item *iamentity.User) error {
	if item == nil {
		return errors.NewCode(errors.InvalidInput, "user is required")
	}
	result, err := s.ExecuteHTTP(ctx, appcrud.ActionUpdate, item.ID, func(_ context.Context, current *iamentity.User) error {
		if current.Version != item.Version {
			return errors.NewCode(errors.Concurrency, "user version has changed")
		}
		*(*userHTTPState)(current) = *(*userHTTPState)(item)
		return nil
	})
	if err == nil {
		*(*userHTTPState)(item) = *(*userHTTPState)(result)
	}
	return err
}

func (s *UserService) DeleteHTTP(ctx context.Context, id int64) error {
	return s.DeleteBulkHTTP(ctx, []int64{id})
}

func (s *UserService) DeleteBulkHTTP(ctx context.Context, ids []int64) error {
	command, err := newUserHTTPExistingCommand(s.httpExisting, appcrud.ActionDelete, func(ctx context.Context, core *appcrud.Application[*iamentity.User, int64], access *userHTTPExistingAccess) (struct{}, error) {
		return struct{}{}, core.DeleteBulk(ctx, ids)
	})
	if err != nil {
		return err
	}
	_, err = command.Execute(ctx, ids)
	return err
}

func (s *UserService) ExecuteHTTP(ctx context.Context, action string, id int64, fn func(context.Context, *iamentity.User) error, options ...appcrud.ExecOption) (*iamentity.User, error) {
	if fn == nil {
		return nil, errors.NewCode(errors.InvalidInput, "command function cannot be nil")
	}
	command, err := newUserHTTPExistingCommand(s.httpExisting, action, func(ctx context.Context, core *appcrud.Application[*iamentity.User, int64], access *userHTTPExistingAccess) (*iamentity.User, error) {
		return core.Execute(ctx, action, id, access.capture(fn), options...)
	})
	if err != nil {
		return nil, err
	}
	return command.Execute(ctx, []int64{id})
}

func (s *UserService) ExecuteBulkHTTP(ctx context.Context, action string, ids []int64, fn func(context.Context, *iamentity.User) error, options ...appcrud.ExecOption) ([]*iamentity.User, error) {
	if fn == nil {
		return nil, errors.NewCode(errors.InvalidInput, "command function cannot be nil")
	}
	command, err := newUserHTTPExistingCommand(s.httpExisting, action, func(ctx context.Context, core *appcrud.Application[*iamentity.User, int64], access *userHTTPExistingAccess) ([]*iamentity.User, error) {
		return core.ExecuteBulk(ctx, action, ids, access.capture(fn), options...)
	})
	if err != nil {
		return nil, err
	}
	return command.Execute(ctx, ids)
}

func (s *UserService) ExistingAuthorizationBinding(action string) (auth.EntryBinding, error) {
	if s == nil || s.httpExisting == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "user HTTP existing application is required")
	}
	if action == appcrud.ActionRead || action == appcrud.ActionCreate {
		return s.httpExisting.core.AuthorizationBinding(action)
	}
	command, err := newUserHTTPExistingCommand[*iamentity.User](s.httpExisting, action, nil)
	if err != nil {
		return auth.EntryBinding{}, err
	}
	return command.AuthorizationBinding()
}
