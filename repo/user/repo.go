package user

import (
	"context"
	"time"

	iamaccess "gochen-iam/access"
	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	assocguard "gochen-iam/repo/internal/guard"
	appcrud "gochen/app/crud"
	"gochen/auth"
	"gochen/auth/access"
	"gochen/db/orm"
	"gochen/db/orm/repo"
	"gochen/db/query"
	domaincrud "gochen/domain/crud"
	"gochen/errors"
	"gochen/ident"
)

// UserRepo 用户数据访问层
type UserRepo struct {
	*repo.Repo[*iamentity.User, int64]
}

type RoleBindingDetail struct {
	BindingID    int64
	RoleID       int64
	GrantScopeID int64
	Status       string
}

type BindingRecord struct {
	BindingID    int64
	UserID       int64
	RoleID       int64
	GrantScopeID int64
	Status       string
}

const (
	userResourceKind  = "iam.user"
	groupResourceKind = "iam.group"
	roleResourceKind  = "iam.role"
)

func (r *UserRepo) tenantScopedQuery(ctx context.Context) (*repo.ScopedQuery, error) {
	query, err := r.Repo.ScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	tenantID, err := appcrud.ResolveTenantID(ctx)
	if err != nil {
		return nil, err
	}
	return query.Where("tenant_id = ?", tenantID), nil
}

func (r *UserRepo) findOne(ctx context.Context, configure func(*repo.ScopedQuery)) (*iamentity.User, error) {
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	if configure != nil {
		configure(query)
	}
	var user *iamentity.User
	if err := query.First(&user); err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepo) getByID(ctx context.Context, id int64) (*iamentity.User, error) {
	return r.findOne(ctx, func(q *repo.ScopedQuery) {
		q.Where("id = ?", id)
	})
}

// NewUserRepository 创建用户仓储。
func NewUserRepository(o orm.IOrm) (*UserRepo, error) {
	base, err := repo.NewRepo[*iamentity.User, int64](
		o,
		"users",
		repo.WithIDGenerator[*iamentity.User, int64](ident.DefaultInt64Generator()),
		repo.WithResourceKind[*iamentity.User, int64]("iam.user"),
		repo.WithSoftDeleteColumns[*iamentity.User, int64]("deleted_at", ""),
		repo.WithAccessColumns[*iamentity.User, int64]("managed_scope_id", "owner_id", "version"),
	)
	if err != nil {
		return nil, err
	}
	return &UserRepo{Repo: base}, nil
}

// shared 原生 ICRUDRepository 方法由 CrudBase 提供

// Create 覆盖通用创建，省略非表字段（version/created_by/updated_by/deleted_by）
func (r *UserRepo) Create(ctx context.Context, u *iamentity.User) error {
	tenantID, err := appcrud.ResolveTenantID(ctx)
	if err == nil {
		if u.TenantID == "" {
			u.TenantID = tenantID
		} else if u.TenantID != tenantID {
			return errors.NewCode(errors.Forbidden, "跨租户访问被拒绝")
		}
	} else if !errors.Is(err, errors.InvalidInput) {
		return err
	}
	if u.HomeTenantID == "" {
		u.HomeTenantID = u.TenantID
	}
	if u.ManagedScopeID == 0 {
		u.ManagedScopeID = managedScopeFromContext(ctx)
	}
	if u.HomeScopeID == 0 {
		u.HomeScopeID = u.ManagedScopeID
	}
	if u.OwnerID == "" {
		u.OwnerID = tenantOwnerID(u.TenantID)
	}
	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	return model.Create(ctx, u)
}

// Update 覆盖通用更新，省略非表字段
func (r *UserRepo) Update(ctx context.Context, u *iamentity.User) error {
	tenantID, err := appcrud.ResolveTenantID(ctx)
	if err != nil {
		return err
	}
	if u.TenantID == "" {
		u.TenantID = tenantID
	} else if u.TenantID != tenantID {
		return errors.NewCode(errors.Forbidden, "跨租户访问被拒绝")
	}
	if u.HomeTenantID == "" {
		u.HomeTenantID = u.TenantID
	}
	if u.ManagedScopeID == 0 {
		u.ManagedScopeID = managedScopeFromContext(ctx)
	}
	if u.HomeScopeID == 0 {
		u.HomeScopeID = u.ManagedScopeID
	}
	if u.OwnerID == "" {
		u.OwnerID = tenantOwnerID(u.TenantID)
	}
	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	return model.Save(ctx, u, orm.WithWhere("id = ? AND tenant_id = ? AND deleted_at IS NULL", u.GetID(), tenantID))
}

// CreateWithConstraint 在显式写边界下创建用户。
func (r *UserRepo) CreateWithConstraint(ctx context.Context, u *iamentity.User, guard iamaccess.WriteConstraint) error {
	return r.Repo.CreateWithConstraint(assocguard.BindContext(ctx, guard), u, guard.Unwrap())
}

// UpdateWithConstraint 在显式写边界下更新用户。
func (r *UserRepo) UpdateWithConstraint(ctx context.Context, u *iamentity.User, guard iamaccess.WriteConstraint) error {
	return r.Repo.UpdateWithConstraint(assocguard.BindContext(ctx, guard), u, guard.Unwrap())
}

// DeleteWithConstraint 在显式写边界下删除用户。
func (r *UserRepo) DeleteWithConstraint(ctx context.Context, id int64, guard iamaccess.WriteConstraint) error {
	return r.Repo.DeleteWithConstraint(assocguard.BindContext(ctx, guard), id, guard.Unwrap())
}

// Query 覆盖通用查询，补齐用户分页列表所需的角色/组织关联。
func (r *UserRepo) Query(ctx context.Context, opts query.QueryOptions) ([]*iamentity.User, error) {
	users, err := r.Repo.Query(ctx, opts)
	if err != nil {
		return nil, err
	}
	return r.hydrateUsersRelations(ctx, users)
}

func (r *UserRepo) CountByHomeScopeID(ctx context.Context, scopeID int64) (int64, error) {
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.User](),
		Table:        "users",
	})
	if err != nil {
		return 0, errors.Wrap(err, errors.Database, "初始化 users 模型失败")
	}
	count, err := model.Count(ctx,
		orm.WithWhere("home_scope_id = ? AND deleted_at IS NULL", scopeID),
	)
	if err != nil {
		return 0, errors.Wrap(err, errors.Database, "统计用户 home scope 引用失败")
	}
	return count, nil
}

func (r *UserRepo) CountByManagedScopeID(ctx context.Context, scopeID int64) (int64, error) {
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.User](),
		Table:        "users",
	})
	if err != nil {
		return 0, errors.Wrap(err, errors.Database, "初始化 users 模型失败")
	}
	count, err := model.Count(ctx,
		orm.WithWhere("managed_scope_id = ? AND deleted_at IS NULL", scopeID),
	)
	if err != nil {
		return 0, errors.Wrap(err, errors.Database, "统计用户 managed scope 引用失败")
	}
	return count, nil
}

func (r *UserRepo) CountRoleBindingsByGrantScopeID(ctx context.Context, scopeID int64) (int64, error) {
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.UserRoleBinding](),
		Table:        "user_role_bindings",
	})
	if err != nil {
		return 0, errors.Wrap(err, errors.Database, "初始化 user_role_bindings 模型失败")
	}
	count, err := model.Count(ctx,
		orm.WithWhere("grant_scope_id = ?", scopeID),
	)
	if err != nil {
		return 0, errors.Wrap(err, errors.Database, "统计用户角色绑定 scope 引用失败")
	}
	return count, nil
}

// Get 根据ID获取用户。
func (r *UserRepo) Get(ctx context.Context, id int64) (*iamentity.User, error) {
	user, err := r.getByID(ctx, id)
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "用户不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询用户失败")
	}
	return user, nil
}

// FindWithRelations 根据ID获取用户及关联数据
func (r *UserRepo) FindWithRelations(ctx context.Context, id int64) (*iamentity.User, error) {
	user, err := r.Repo.GetWith(ctx, id, func(q *repo.ScopedQuery) {
		q.Preload("Groups", "Roles")
	})
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "用户不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询用户失败")
	}
	return user, nil
}

// FindByEmail 根据邮箱查找用户（租户内唯一）。
func (r *UserRepo) FindByEmail(ctx context.Context, email string) (*iamentity.User, error) {
	user, err := r.findOne(ctx, func(q *repo.ScopedQuery) {
		q.Where("email = ?", email).Preload("Groups", "Roles")
	})
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "用户不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询用户失败")
	}

	return user, nil
}

// FindByUsername 根据用户名查找用户（租户内唯一）。
func (r *UserRepo) FindByUsername(ctx context.Context, username string) (*iamentity.User, error) {
	user, err := r.findOne(ctx, func(q *repo.ScopedQuery) {
		q.Where("username = ?", username).Preload("Groups", "Roles")
	})
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "用户不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询用户失败")
	}

	return user, nil
}

// UpdateLastLogin 更新最后登录时间
func (r *UserRepo) UpdateLastLogin(ctx context.Context, userID int64) error {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.UpdateValues(ctx, map[string]any{
		"last_login_at": time.Now(),
	}, orm.WithWhere("id = ? AND deleted_at IS NULL", userID))

	if err != nil {
		return errors.Wrap(err, errors.Database, "更新最后登录时间失败")
	}

	return nil
}

// FindByStatus 根据状态查找用户。
func (r *UserRepo) FindByStatus(ctx context.Context, status string) ([]*iamentity.User, error) {
	var users []*iamentity.User
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	err = query.
		Where("status = ?", status).
		Preload("Groups", "Roles").
		Find(&users)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询用户失败")
	}

	return users, nil
}

// FindByGroupID 根据组织ID查找用户。
func (r *UserRepo) FindByGroupID(ctx context.Context, groupID int64) ([]*iamentity.User, error) {
	var users []*iamentity.User
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	err = query.
		Join(orm.InnerJoin("user_groups", "", orm.On("users.id", "user_groups.user_id"))).
		Where("user_groups.group_id = ?", groupID).
		Preload("Groups", "Roles").
		Find(&users)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询组织用户失败")
	}

	return users, nil
}

// FindByRoleID 根据角色ID查找用户。
func (r *UserRepo) FindByRoleID(ctx context.Context, roleID int64) ([]*iamentity.User, error) {
	var users []*iamentity.User
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	err = query.
		Join(orm.InnerJoin("user_role_bindings", "", orm.On("users.id", "user_role_bindings.user_id"))).
		Where("user_role_bindings.role_id = ?", roleID).
		Where("user_role_bindings.status = ?", "active").
		Preload("Groups", "Roles").
		Find(&users)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询角色用户失败")
	}

	return users, nil
}

// CountByRoleID 统计拥有指定角色的用户数量（不依赖 preload）
func (r *UserRepo) CountByRoleID(ctx context.Context, roleID int64) (int64, error) {
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	userRoleModel, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[struct {
			RoleID int64
			UserID int64
		}](),
		Table: "user_role_bindings",
	})
	if err != nil {
		return 0, errors.Wrap(err, errors.Database, "初始化 user_role_bindings 模型失败")
	}
	count, err := userRoleModel.Count(ctx,
		orm.WithWhere("role_id = ?", roleID),
		orm.WithWhere("status = ?", "active"),
	)
	if err != nil {
		return 0, errors.Wrap(err, errors.Database, "统计角色用户数量失败")
	}
	return count, nil
}

// ListRoleBindings 返回用户当前生效的直接角色绑定。
func (r *UserRepo) ListRoleBindings(ctx context.Context, userID int64) ([]RoleBindingDetail, error) {
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.UserRoleBinding](),
		Table:        "user_role_bindings",
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "初始化 user_role_bindings 模型失败")
	}
	var bindings []*iamentity.UserRoleBinding
	if err := model.Find(ctx, &bindings,
		orm.WithWhere("user_id = ?", userID),
		orm.WithWhere("status = ?", "active"),
	); err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询用户角色绑定失败")
	}
	result := make([]RoleBindingDetail, 0, len(bindings))
	for _, binding := range bindings {
		if binding == nil {
			continue
		}
		result = append(result, RoleBindingDetail{
			BindingID:    binding.ID,
			RoleID:       binding.RoleID,
			GrantScopeID: binding.GrantScopeID,
			Status:       binding.Status,
		})
	}
	return result, nil
}

// GetRoleBinding 返回指定角色绑定。
func (r *UserRepo) GetRoleBinding(ctx context.Context, bindingID int64) (*BindingRecord, error) {
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.UserRoleBinding](),
		Table:        "user_role_bindings",
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "初始化 user_role_bindings 模型失败")
	}
	var binding iamentity.UserRoleBinding
	if err := model.First(ctx, &binding, orm.WithWhere("id = ?", bindingID)); err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "角色绑定不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询角色绑定失败")
	}
	return &BindingRecord{
		BindingID:    binding.ID,
		UserID:       binding.UserID,
		RoleID:       binding.RoleID,
		GrantScopeID: binding.GrantScopeID,
		Status:       binding.Status,
	}, nil
}

// AssignRoleAtScope 在指定 grant scope 下为用户分配角色。
func (r *UserRepo) AssignRoleAtScope(ctx context.Context, userID, roleID, grantScopeID int64) error {
	return r.assignRoleAtScope(ctx, userID, roleID, grantScopeID, true)
}

func (r *UserRepo) assignRoleAtScope(ctx context.Context, userID, roleID, grantScopeID int64, validateRole bool) error {
	if _, err := r.getByID(ctx, userID); err != nil {
		return err
	}
	if validateRole {
		if _, err := r.roleByID(ctx, roleID); err != nil {
			return err
		}
	}
	if grantScopeID <= 0 {
		return errors.NewCode(errors.InvalidInput, "grant scope is required")
	}
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.UserRoleBinding](),
		Table:        "user_role_bindings",
	})
	if err != nil {
		return errors.Wrap(err, errors.Database, "初始化 user_role_bindings 模型失败")
	}
	binding := &iamentity.UserRoleBinding{
		UserID:       userID,
		RoleID:       roleID,
		GrantScopeID: grantScopeID,
		Status:       "active",
	}
	if err := model.Create(ctx, binding); err != nil {
		return errors.Wrap(err, errors.Database, "分配角色失败")
	}
	return nil
}

// RemoveRoleBinding 删除指定角色绑定。
func (r *UserRepo) RemoveRoleBinding(ctx context.Context, bindingID int64) error {
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.UserRoleBinding](),
		Table:        "user_role_bindings",
	})
	if err != nil {
		return errors.Wrap(err, errors.Database, "初始化 user_role_bindings 模型失败")
	}
	if err := model.Delete(ctx, orm.WithWhere("id = ?", bindingID)); err != nil {
		return errors.Wrap(err, errors.Database, "移除角色绑定失败")
	}
	return nil
}

// AssignToGroup 将用户分配到组织
func (r *UserRepo) AssignToGroup(ctx context.Context, userID, groupID int64) error {
	user, err := r.getByID(ctx, userID)
	if err != nil {
		return err
	}

	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.Association(user, "Groups").
		Append(ctx, &iamentity.Group{Entity: domaincrud.Entity[int64]{ID: groupID}})

	if err != nil {
		return errors.Wrap(err, errors.Database, "分配用户到组织失败")
	}

	return nil
}

// AssignToGroupWithConstraint 在显式多资源写边界下把用户加入组织。
func (r *UserRepo) AssignToGroupWithConstraint(ctx context.Context, userID, groupID int64, guard iamaccess.WriteConstraint) error {
	return r.mutateUserAssociationWithConstraint(
		ctx,
		userID,
		"Groups",
		groupResourceKind,
		groupID,
		&iamentity.Group{Entity: domaincrud.Entity[int64]{ID: groupID}},
		false,
		"分配用户到组织失败",
		guard,
	)
}

// RemoveFromGroup 从组织中移除用户
func (r *UserRepo) RemoveFromGroup(ctx context.Context, userID, groupID int64) error {
	user, err := r.getByID(ctx, userID)
	if err != nil {
		return err
	}

	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.Association(user, "Groups").
		Delete(ctx, &iamentity.Group{Entity: domaincrud.Entity[int64]{ID: groupID}})

	if err != nil {
		return errors.Wrap(err, errors.Database, "从组织移除用户失败")
	}

	return nil
}

// RemoveFromGroupWithConstraint 在显式多资源写边界下把用户移出组织。
func (r *UserRepo) RemoveFromGroupWithConstraint(ctx context.Context, userID, groupID int64, guard iamaccess.WriteConstraint) error {
	return r.mutateUserAssociationWithConstraint(
		ctx,
		userID,
		"Groups",
		groupResourceKind,
		groupID,
		&iamentity.Group{Entity: domaincrud.Entity[int64]{ID: groupID}},
		true,
		"从组织移除用户失败",
		guard,
	)
}

// AssignRole 为用户分配角色
func (r *UserRepo) AssignRole(ctx context.Context, userID, roleID int64) error {
	role, err := r.roleByID(ctx, roleID)
	if err != nil {
		return err
	}
	grantScopeID := role.NamespaceScopeID
	if override := managedScopeFromContext(ctx); override > 0 {
		grantScopeID = override
	}
	return r.assignRoleAtScope(ctx, userID, roleID, grantScopeID, false)
}

func managedScopeFromContext(ctx context.Context) int64 {
	if scopeID := iamauth.ActiveScopeIDFromContext(ctx); scopeID > 0 {
		return scopeID
	}
	if scope, ok := auth.DataScopeFromContext(ctx); ok {
		if scope.ActiveScopeID > 0 {
			return scope.ActiveScopeID
		}
		if len(scope.VisibleScopeIDs) == 1 {
			return scope.VisibleScopeIDs[0]
		}
	}
	if scope, ok := access.DataScopeFromContext(ctx); ok {
		if scope.ActiveScopeID > 0 {
			return scope.ActiveScopeID
		}
		if len(scope.VisibleScopeIDs) == 1 {
			return scope.VisibleScopeIDs[0]
		}
	}
	if principal, ok := auth.PrincipalFromContext(ctx); ok && principal.ActiveScopeID > 0 {
		return principal.ActiveScopeID
	}
	return 0
}

func tenantOwnerID(tenantID string) string {
	if tenantID == "" {
		return ""
	}
	return "tenant:" + tenantID
}

// AssignRoleWithConstraint 在显式多资源写边界下给用户分配角色。
func (r *UserRepo) AssignRoleWithConstraint(ctx context.Context, userID, roleID int64, guard iamaccess.WriteConstraint) error {
	if _, _, err := assocguard.RequirePair(guard, userResourceKind, userID, roleResourceKind, roleID); err != nil {
		return err
	}
	return r.AssignRole(assocguard.BindContext(ctx, guard), userID, roleID)
}

// RemoveRole 移除用户角色
func (r *UserRepo) RemoveRole(ctx context.Context, userID, roleID int64) error {
	if _, err := r.getByID(ctx, userID); err != nil {
		return err
	}
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.UserRoleBinding](),
		Table:        "user_role_bindings",
	})
	if err != nil {
		return errors.Wrap(err, errors.Database, "初始化 user_role_bindings 模型失败")
	}
	if err := model.Delete(ctx,
		orm.WithWhere("user_id = ?", userID),
		orm.WithWhere("role_id = ?", roleID),
	); err != nil {
		return errors.Wrap(err, errors.Database, "移除角色失败")
	}

	return nil
}

func (r *UserRepo) roleByID(ctx context.Context, roleID int64) (*iamentity.Role, error) {
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.Role](),
		Table:        "roles",
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "初始化 role 模型失败")
	}
	var role iamentity.Role
	if err := model.First(ctx, &role,
		orm.WithWhere("id = ?", roleID),
		orm.WithWhere("deleted_at IS NULL"),
	); err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "角色不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询角色失败")
	}
	return &role, nil
}

// RemoveRoleWithConstraint 在显式多资源写边界下移除用户角色。
func (r *UserRepo) RemoveRoleWithConstraint(ctx context.Context, userID, roleID int64, guard iamaccess.WriteConstraint) error {
	if _, _, err := assocguard.RequirePair(guard, userResourceKind, userID, roleResourceKind, roleID); err != nil {
		return err
	}
	return r.RemoveRole(assocguard.BindContext(ctx, guard), userID, roleID)
}

func (r *UserRepo) mutateUserAssociationWithConstraint(
	ctx context.Context,
	userID int64,
	association string,
	relatedKind string,
	relatedID int64,
	related any,
	remove bool,
	message string,
	guard iamaccess.WriteConstraint,
) error {
	if _, _, err := assocguard.RequirePair(guard, userResourceKind, userID, relatedKind, relatedID); err != nil {
		return err
	}

	user, err := r.getByID(ctx, userID)
	if err != nil {
		return err
	}
	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}

	associationRef := model.Association(user, association)
	if remove {
		err = associationRef.Delete(ctx, related)
	} else {
		err = associationRef.Append(ctx, related)
	}
	if err != nil {
		return errors.Wrap(err, errors.Database, message)
	}
	return nil
}

// CountByStatus 统计各状态用户数量。
func (r *UserRepo) CountByStatus(ctx context.Context) (map[string]int64, error) {
	type StatusCount struct {
		Status string `json:"status"`
		Count  int64  `json:"count"`
	}

	var results []StatusCount
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	err = query.
		Select("status", "COUNT(*) as count").
		GroupBy("status").
		Find(&results)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "统计用户状态失败")
	}

	statusMap := make(map[string]int64)
	for _, result := range results {
		statusMap[result.Status] = result.Count
	}

	return statusMap, nil
}

// SearchUsers 搜索用户（支持用户名、邮箱模糊搜索）。
func (r *UserRepo) SearchUsers(ctx context.Context, keyword string, limit int) ([]*iamentity.User, error) {
	var users []*iamentity.User
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	query.Preload("Groups", "Roles")
	if keyword != "" {
		query.Where("username LIKE ? OR email LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}
	if limit > 0 {
		query.Limit(limit)
	}
	err = query.Find(&users)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "搜索用户失败")
	}

	return users, nil
}

// hydrateUsersRelations 处理填充UsersRelations。
func (r *UserRepo) hydrateUsersRelations(ctx context.Context, users []*iamentity.User) ([]*iamentity.User, error) {
	for i := range users {
		user := users[i]
		if user == nil {
			continue
		}

		hydrated, err := r.FindWithRelations(ctx, user.GetID())
		if err != nil {
			return nil, err
		}

		user.Groups = hydrated.Groups
		user.Roles = hydrated.Roles
	}

	return users, nil
}
