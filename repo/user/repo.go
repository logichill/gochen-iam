package user

import (
	"context"
	"strings"
	"time"

	iamentity "gochen-iam/entity"
	"gochen-iam/repo/internal/likesafe"
	scoperesolver "gochen-iam/repo/internal/scope"
	"gochen-iam/repo/relations"
	iamtenant "gochen-iam/tenant"
	"gochen-runtime/db/orm/repo"
	"gochen/app/query"
	"gochen/contextx"
	"gochen/db/orm"
	domaincrud "gochen/domain/crud"
	"gochen/domain/spec"
	"gochen/errors"
	"gochen/gen"
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

// DisplayRef contains the fields exposed by trusted cross-resource displays.
type DisplayRef struct {
	ID       int64
	Username string
	Email    string
	Avatar   string
}

// FindActiveDisplay reads one same-tenant active user without loading associations.
// Callers supply exactly one trusted ID or username and the resource condition.
func (r *UserRepo) FindActiveDisplay(ctx context.Context, id int64, username string, condition spec.Spec) (*DisplayRef, error) {
	if id < 0 || (id == 0) == (username == "") {
		return nil, errors.NewCode(errors.InvalidInput, "user display requires one ID or username")
	}
	q, err := r.ScopedQueryWithSpec(ctx, condition)
	if err != nil {
		return nil, err
	}
	tenantID, err := (iamtenant.Resolver{}).ResolveTenantID(ctx)
	if err != nil {
		return nil, err
	}
	q.Select("id", "username", "email", "avatar").Where("tenant_id = ?", tenantID).
		Where("(status = ? OR TRIM(status) = '')", "active")
	if id > 0 {
		q.Where("id = ?", id)
	} else {
		q.Where("username = ?", username)
	}
	var ref DisplayRef
	if err := q.First(&ref); err != nil {
		return nil, err
	}
	return &ref, nil
}

const (
	userResourceKind  = "iam.user"
	groupResourceKind = "iam.group"
	roleResourceKind  = "iam.role"
)

func (r *UserRepo) tenantScopedQuery(ctx context.Context) (*repo.ScopedQuery, error) {
	query, err := r.ScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	tenantID, err := (iamtenant.Resolver{}).ResolveTenantID(ctx)
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
func NewUserRepository(o orm.IOrm, idGenerator gen.IGenerator[int64]) (*UserRepo, error) {
	base, err := repo.NewRepo[*iamentity.User, int64](
		o,
		"users",
		repo.WithIDGenerator[*iamentity.User, int64](idGenerator),
		repo.WithResourceKind[*iamentity.User, int64]("iam.user"),
		repo.WithSoftDeleteColumns[*iamentity.User, int64]("deleted_at", ""),
		repo.WithIsolation[*iamentity.User, int64](repo.IsolationCols{Column: "tenant_id"}),
	)
	if err != nil {
		return nil, err
	}
	return &UserRepo{Repo: base}, nil
}

// shared 原生 ICRUDRepository 方法由 CrudBase 提供

// Create 补齐用户租户边界，并通过 Runtime Repo 执行受控创建。
func (r *UserRepo) Create(ctx context.Context, u *iamentity.User, s spec.Spec) error {
	tenantID, err := (iamtenant.Resolver{}).ResolveTenantID(ctx)
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
		u.ManagedScopeID = scoperesolver.ResolveManagedScopeID(ctx)
	}
	if u.HomeScopeID == 0 {
		u.HomeScopeID = u.ManagedScopeID
	}
	if u.OwnerID == "" {
		u.OwnerID = tenantOwnerID(u.TenantID)
	}
	return r.Repo.Create(ctx, u, s)
}

// Update 去除关联字段，通过 Runtime Repo 原子校验租户、范围与版本。
func (r *UserRepo) Update(ctx context.Context, u *iamentity.User, s spec.Spec) error {
	tenantID, err := (iamtenant.Resolver{}).ResolveTenantID(ctx)
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
		u.ManagedScopeID = scoperesolver.ResolveManagedScopeID(ctx)
	}
	if u.HomeScopeID == 0 {
		u.HomeScopeID = u.ManagedScopeID
	}
	if u.OwnerID == "" {
		u.OwnerID = tenantOwnerID(u.TenantID)
	}
	updated := userWithoutAssociations(u)
	if err := r.Repo.Update(ctx, updated, s); err != nil {
		return err
	}
	u.Version = updated.GetVersion()
	u.SetUpdatedAt(updated.GetUpdatedAt())
	return nil
}

func userWithoutAssociations(user *iamentity.User) *iamentity.User {
	if user == nil {
		return nil
	}
	return &iamentity.User{
		Entity:         user.Entity,
		Timestamps:     user.Timestamps,
		DeletedAt:      user.DeletedAt,
		TenantID:       user.TenantID,
		HomeTenantID:   user.HomeTenantID,
		HomeScopeID:    user.HomeScopeID,
		ManagedScopeID: user.ManagedScopeID,
		OwnerID:        user.OwnerID,
		Username:       user.Username,
		Email:          user.Email,
		Password:       user.Password,
		Status:         user.Status,
		Avatar:         user.Avatar,
		LastLoginAt:    user.LastLoginAt,
	}
}

// Delete 执行软删除并保留 IAM 既有语义；物理删除请使用 Purge。
func (r *UserRepo) Delete(ctx context.Context, user *iamentity.User, s spec.Spec) error {
	if user == nil {
		return errors.NewCode(errors.InvalidInput, "user cannot be nil")
	}
	if user.IsDeleted() {
		return errors.NewCode(errors.Conflict, "用户已删除").WithContext("id", user.GetID())
	}
	user.MarkAsDeleted()
	return r.Repo.Update(ctx, userWithoutAssociations(user), s)
}

// Query 覆盖通用查询，补齐用户分页列表所需的角色/组织关联。
func (r *UserRepo) Query(ctx context.Context, opts query.QueryOptions, s spec.Spec) ([]*iamentity.User, error) {
	users, err := r.Repo.Query(ctx, opts, s)
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
	tenantID := strings.TrimSpace(contextx.TenantID(ctx))
	whereOpts := []orm.QueryOption{
		orm.WithWhere("home_scope_id = ? AND deleted_at IS NULL", scopeID),
	}
	if tenantID != "" {
		whereOpts = append([]orm.QueryOption{orm.WithWhere("tenant_id = ?", tenantID)}, whereOpts...)
	}
	count, err := model.Count(ctx, whereOpts...)
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
	tenantID := strings.TrimSpace(contextx.TenantID(ctx))
	whereOpts := []orm.QueryOption{
		orm.WithWhere("managed_scope_id = ? AND deleted_at IS NULL", scopeID),
	}
	if tenantID != "" {
		whereOpts = append([]orm.QueryOption{orm.WithWhere("tenant_id = ?", tenantID)}, whereOpts...)
	}
	count, err := model.Count(ctx, whereOpts...)
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
func (r *UserRepo) Get(ctx context.Context, id int64, s spec.Spec) (*iamentity.User, error) {
	user, err := r.Repo.Get(ctx, id, s)
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
	user, err := r.GetWith(ctx, id, func(q *repo.ScopedQuery) {
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
	tenantID, err := (iamtenant.Resolver{}).ResolveTenantID(ctx)
	if err != nil {
		return err
	}
	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.UpdateValues(ctx, map[string]any{
		"last_login_at": time.Now(),
	}, orm.WithWhere("id = ? AND tenant_id = ? AND deleted_at IS NULL", userID, tenantID))

	if err != nil {
		return errors.Wrap(err, errors.Database, "更新最后登录时间失败")
	}

	return nil
}

// FindByStatus 根据状态查找用户。
func (r *UserRepo) FindByStatus(ctx context.Context, status string, condition spec.Spec) ([]*iamentity.User, error) {
	var users []*iamentity.User
	query, err := r.ScopedQueryWithSpec(ctx, condition)
	if err != nil {
		return nil, err
	}
	tenantID, err := (iamtenant.Resolver{}).ResolveTenantID(ctx)
	if err != nil {
		return nil, err
	}
	err = query.
		Where("tenant_id = ?", tenantID).
		Where("status = ?", status).
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

// RemoveAuthorizedRoleBinding 仅删除已授权的绑定快照，并校验用户与角色的写入边界。
func (r *UserRepo) RemoveAuthorizedRoleBinding(ctx context.Context, binding BindingRecord, userCondition, roleCondition spec.Spec) error {
	return r.WithinTx(ctx, func(txCtx context.Context) error {
		user, err := r.Repo.Get(txCtx, binding.UserID, userCondition)
		if err != nil {
			return err
		}
		role, err := r.roleByID(txCtx, binding.RoleID)
		if err != nil {
			return err
		}
		if user.TenantID != role.TenantID {
			return errors.NewCode(errors.Forbidden, "user and role must belong to the same tenant")
		}
		if err := requireSpecMatch(roleCondition, role); err != nil {
			return err
		}
		session, ok := orm.SessionFromContext(txCtx)
		if !ok || session == nil {
			return errors.NewCode(errors.Internal, "orm session is required in transaction context")
		}
		model, err := session.Model(&orm.ModelMeta{
			ModelFactory: orm.NewModelFactory[iamentity.UserRoleBinding](),
			Table:        "user_role_bindings",
		})
		if err != nil {
			return err
		}
		writer, ok := model.(orm.IModelWithResult)
		if !ok {
			return errors.NewCode(errors.Unsupported, "constrained binding deletion requires write results")
		}
		result, err := writer.DeleteWithResult(txCtx,
			orm.WithWhere("id = ? AND user_id = ? AND role_id = ? AND grant_scope_id = ? AND status = ?",
				binding.BindingID, binding.UserID, binding.RoleID, binding.GrantScopeID, binding.Status),
		)
		if err != nil {
			return err
		}
		if result == nil {
			return errors.NewCode(errors.Internal, "binding deletion did not return a write result")
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected != 1 {
			return errors.NewCode(errors.Conflict, "role binding changed after authorization")
		}
		return nil
	})
}

// AssignToGroup 将用户分配到组织。
func (r *UserRepo) AssignToGroup(ctx context.Context, userID, groupID int64, userCondition, groupCondition spec.Spec) error {
	return r.mutateUserAssociation(ctx, userID, "Groups", groupResourceKind, groupID,
		&iamentity.Group{Entity: domaincrud.Entity[int64]{ID: groupID}}, false, "分配用户到组织失败", userCondition, groupCondition)
}

// RemoveFromGroup 从组织中移除用户。
func (r *UserRepo) RemoveFromGroup(ctx context.Context, userID, groupID int64, userCondition, groupCondition spec.Spec) error {
	return r.mutateUserAssociation(ctx, userID, "Groups", groupResourceKind, groupID,
		&iamentity.Group{Entity: domaincrud.Entity[int64]{ID: groupID}}, true, "从组织移除用户失败", userCondition, groupCondition)
}

// AssignRole 为用户分配角色。
func (r *UserRepo) AssignRole(ctx context.Context, userID, roleID, grantScopeID int64, userCondition, roleCondition spec.Spec) error {
	return r.WithinTx(ctx, func(txCtx context.Context) error {
		if _, err := r.Repo.Get(txCtx, userID, userCondition); err != nil {
			return err
		}
		role, err := r.roleByID(txCtx, roleID)
		if err != nil {
			return err
		}
		if err := requireSpecMatch(roleCondition, role); err != nil {
			return err
		}
		return r.assignRoleAtScope(txCtx, userID, roleID, grantScopeID, false)
	})
}

func tenantOwnerID(tenantID string) string {
	if tenantID == "" {
		return ""
	}
	return "tenant:" + tenantID
}

// RemoveRole 移除用户角色。
func (r *UserRepo) RemoveRole(ctx context.Context, userID, roleID int64, userCondition, roleCondition spec.Spec) error {
	return r.WithinTx(ctx, func(txCtx context.Context) error {
		user, err := r.Repo.Get(txCtx, userID, userCondition)
		if err != nil {
			return err
		}
		role, err := r.roleByID(txCtx, roleID)
		if err != nil {
			return err
		}
		if user.TenantID != role.TenantID {
			return errors.NewCode(errors.Forbidden, "user and role must belong to the same tenant")
		}
		if err := requireSpecMatch(roleCondition, role); err != nil {
			return err
		}
		session, ok := orm.SessionFromContext(txCtx)
		if !ok || session == nil {
			return errors.NewCode(errors.Internal, "orm session is required in transaction context")
		}
		model, err := session.Model(&orm.ModelMeta{
			ModelFactory: orm.NewModelFactory[iamentity.UserRoleBinding](),
			Table:        "user_role_bindings",
		})
		if err != nil {
			return errors.Wrap(err, errors.Database, "初始化 user_role_bindings 模型失败")
		}
		if err := model.Delete(txCtx,
			orm.WithWhere("user_id = ?", userID),
			orm.WithWhere("role_id = ?", roleID),
		); err != nil {
			return errors.Wrap(err, errors.Database, "移除角色失败")
		}
		return nil
	})
}

func (r *UserRepo) roleByID(ctx context.Context, roleID int64) (*iamentity.Role, error) {
	tenantID, err := (iamtenant.Resolver{}).ResolveTenantID(ctx)
	if err != nil {
		return nil, err
	}
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
		orm.WithWhere("tenant_id = ?", tenantID),
		orm.WithWhere("deleted_at IS NULL"),
	); err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "角色不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询角色失败")
	}
	return &role, nil
}

func (r *UserRepo) groupByID(ctx context.Context, groupID int64) (*iamentity.Group, error) {
	tenantID, err := (iamtenant.Resolver{}).ResolveTenantID(ctx)
	if err != nil {
		return nil, err
	}
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.Group](),
		Table:        "groups",
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "初始化 groups 模型失败")
	}
	var group iamentity.Group
	if err := model.First(ctx, &group,
		orm.WithWhere("id = ?", groupID),
		orm.WithWhere("tenant_id = ?", tenantID),
		orm.WithWhere("deleted_at IS NULL"),
	); err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "组织不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询组织失败")
	}
	return &group, nil
}

func (r *UserRepo) mutateUserAssociation(
	ctx context.Context,
	userID int64,
	association string,
	relatedKind string,
	relatedID int64,
	related any,
	remove bool,
	message string,
	userCondition, relatedCondition spec.Spec,
) error {
	return r.WithinTx(ctx, func(txCtx context.Context) error {
		user, err := r.Repo.Get(txCtx, userID, userCondition)
		if err != nil {
			return err
		}
		if err := r.requireRelatedInSpec(txCtx, relatedKind, relatedID, relatedCondition); err != nil {
			return err
		}
		model, err := r.ModelFor(txCtx)
		if err != nil {
			return err
		}
		associationRef := model.Association(user, association)
		if remove {
			err = associationRef.Delete(txCtx, related)
		} else {
			err = associationRef.Append(txCtx, related)
		}
		if err != nil {
			return errors.Wrap(err, errors.Database, message)
		}
		return nil
	})
}

func (r *UserRepo) requireRelatedInSpec(ctx context.Context, kind string, id int64, s spec.Spec) error {
	switch kind {
	case roleResourceKind:
		role, err := r.roleByID(ctx, id)
		if err != nil {
			return err
		}
		return requireSpecMatch(s, role)
	case groupResourceKind:
		group, err := r.groupByID(ctx, id)
		if err != nil {
			return err
		}
		return requireSpecMatch(s, group)
	default:
		return errors.NewCode(errors.InvalidInput, "unsupported related resource kind").
			WithContext("kind", kind)
	}
}

func requireSpecMatch(s spec.Spec, entity any) error {
	if s.Err() != nil {
		return s.Err()
	}
	ok, err := spec.NewInterpreter().Match(s, entity)
	if err != nil {
		return err
	}
	if !ok {
		return errors.NewCode(errors.Forbidden, "entity does not satisfy the required scope")
	}
	return nil
}

// MembersForGroups reads authorized users and their links without preloading relations.
func (r *UserRepo) MembersForGroups(ctx context.Context, groupIDs []int64, condition spec.Spec) (relations.Catalog[*iamentity.User], error) {
	return relations.Read(ctx, r.Repo, groupIDs, condition, orm.InnerJoin("user_groups", "", orm.On("users.id", "user_groups.user_id")), "user_groups.group_id", "users.id")
}

// GroupMemberCounts counts authorized users for the specified groups without preloading relations.
func (r *UserRepo) GroupMemberCounts(ctx context.Context, groupIDs []int64, s spec.Spec) (map[int64]int64, error) {
	counts := make(map[int64]int64)
	for _, id := range groupIDs {
		if id <= 0 {
			return nil, errors.NewCode(errors.InvalidInput, "group ID must be positive")
		}
	}
	const batchSize = 1000
	for start := 0; start < len(groupIDs); start += batchSize {
		end := min(start+batchSize, len(groupIDs))
		q, err := r.ScopedQueryWithSpec(ctx, s)
		if err != nil {
			return nil, err
		}
		var rows []struct {
			GroupID int64
			Total   int64
		}
		err = q.Join(orm.InnerJoin("user_groups", "", orm.On("users.id", "user_groups.user_id"))).
			Where("user_groups.group_id IN ?", groupIDs[start:end]).
			SelectExprUnsafe(repo.AllowUnsafeSelectExpr(), "user_groups.group_id AS group_id", "COUNT(DISTINCT users.id) AS total").
			GroupBy("user_groups.group_id").Find(&rows)
		if err != nil {
			return nil, errors.Wrap(err, errors.Database, "count group members")
		}
		for _, row := range rows {
			counts[row.GroupID] = row.Total
		}
	}
	return counts, nil
}

// CountByStatus 统计各状态用户数量。
func (r *UserRepo) CountByStatus(ctx context.Context, s spec.Spec) (map[string]int64, error) {
	statusMap := make(map[string]int64)
	const pageSize = 1000
	for offset := 0; ; offset += pageSize {
		// 只统计 id/status 投影，绕过 Query 覆盖以跳过关联补齐。
		users, err := r.Repo.Query(ctx, query.QueryOptions{
			Offset: offset,
			Limit:  pageSize,
			Fields: []string{"id", "status"},
		}, s)
		if err != nil {
			return nil, errors.Wrap(err, errors.Database, "统计用户状态失败")
		}
		for _, user := range users {
			if user != nil {
				statusMap[user.Status]++
			}
		}
		if len(users) < pageSize {
			return statusMap, nil
		}
	}
}

// SearchUsers 搜索用户（支持用户名、邮箱模糊搜索）。
func (r *UserRepo) SearchUsers(ctx context.Context, keyword string, limit int, condition spec.Spec) ([]*iamentity.User, error) {
	var users []*iamentity.User
	query, err := r.ScopedQueryWithSpec(ctx, condition)
	if err != nil {
		return nil, err
	}
	tenantID, err := (iamtenant.Resolver{}).ResolveTenantID(ctx)
	if err != nil {
		return nil, err
	}
	query.Where("tenant_id = ?", tenantID)
	if keyword != "" {
		pattern := likesafe.ContainsPattern(keyword)
		query.Where("(username LIKE ?"+likesafe.EscapeClause+" OR email LIKE ?"+likesafe.EscapeClause+")", pattern, pattern)
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

// MembersForRoles projects same-tenant users under an independent user condition.
func (r *UserRepo) MembersForRoles(ctx context.Context, roleIDs []int64, condition spec.Spec) (relations.Catalog[*iamentity.User], error) {
	return relations.Read(ctx, r.Repo, roleIDs, condition, orm.InnerJoin("user_role_bindings", "", orm.On("users.id", "user_role_bindings.user_id")), "user_role_bindings.role_id", "users.id", orm.Condition{Expr: "user_role_bindings.status = ?", Args: []any{"active"}})
}
