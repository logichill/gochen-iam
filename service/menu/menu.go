package menu

import (
	"context"
	"sort"
	"time"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	menurepo "gochen-iam/repo/menu"
	svc "gochen-iam/service"
	"gochen/authz"
	"gochen/errorx"
	"gochen/httpx"
	"gochen/logging"
)

// MenuService 负责菜单定义管理与当前用户菜单树组装。
type MenuService struct {
	menuRepo   *menurepo.MenuItemRepo
	authorizer authz.IAuthorizer
	logger     logging.ILogger
}

// NewMenuService 创建菜单应用服务。
func NewMenuService(menuRepo *menurepo.MenuItemRepo, authorizer *authz.Authorizer) *MenuService {
	var authzEngine authz.IAuthorizer
	if authorizer != nil {
		authzEngine = authorizer
	}
	return &MenuService{
		menuRepo:   menuRepo,
		authorizer: authzEngine,
		logger:     logging.ComponentLogger("iam.service.menu"),
	}
}

// CreateMenuItemRequest 定义创建菜单的请求体。
type CreateMenuItemRequest struct {
	Code      string `json:"code" binding:"required,max=100"`
	ParentID  *int64 `json:"parent_id,omitempty" binding:"omitempty,gt=0"`
	Title     string `json:"title" binding:"required,max=200"`
	Path      string `json:"path,omitempty" binding:"omitempty,max=500"`
	Icon      string `json:"icon,omitempty" binding:"omitempty,max=200"`
	Type      string `json:"type" binding:"omitempty,oneof=group page link"`
	Order     int    `json:"order" binding:"omitempty,gte=0"`
	Route     string `json:"route,omitempty" binding:"omitempty,max=500"`
	Component string `json:"component,omitempty" binding:"omitempty,max=500"`

	Hidden    bool `json:"hidden"`
	Disabled  bool `json:"disabled"`
	Published bool `json:"published"`

	AnyOfPermissions []string `json:"any_of_permissions,omitempty"`
	AllOfPermissions []string `json:"all_of_permissions,omitempty"`
}

// UpdateMenuItemRequest 定义更新菜单的请求体。
//
// 说明：
// - 普通字段继续沿用 request DTO；
// - `parent_id` 需要区分“缺失/null/具体值”，因此 router 会把字段出现语义翻译成 `FieldPatch`；
// - service 层不直接依赖 `ParentID` 是否为 nil 来判断是否更新父级。
type UpdateMenuItemRequest struct {
	ParentID *int64 `json:"parent_id,omitempty"`

	Title     string  `json:"title,omitempty" binding:"omitempty,max=200"`
	Path      *string `json:"path,omitempty" binding:"omitempty,max=500"`
	Icon      *string `json:"icon,omitempty" binding:"omitempty,max=200"`
	Type      string  `json:"type,omitempty" binding:"omitempty,oneof=group page link"`
	Order     *int    `json:"order,omitempty"`
	Route     *string `json:"route,omitempty" binding:"omitempty,max=500"`
	Component *string `json:"component,omitempty" binding:"omitempty,max=500"`

	Hidden    *bool `json:"hidden,omitempty"`
	Disabled  *bool `json:"disabled,omitempty"`
	Published *bool `json:"published,omitempty"`

	AnyOfPermissions []string `json:"any_of_permissions,omitempty"`
	AllOfPermissions []string `json:"all_of_permissions,omitempty"`
}

// SyncMenuItemRequest 定义单个菜单同步项。
type SyncMenuItemRequest struct {
	Code string `json:"code" binding:"required,max=100"`
	// Sync 场景面向声明式菜单定义，使用稳定的业务 code 建树，再在服务层解析成 ParentID 落库。
	ParentCode string `json:"parent_code,omitempty" binding:"omitempty,max=100"`

	Title string `json:"title" binding:"required,max=200"`
	Path  string `json:"path,omitempty" binding:"omitempty,max=500"`
	Icon  string `json:"icon,omitempty" binding:"omitempty,max=200"`
	Type  string `json:"type" binding:"omitempty,oneof=group page link"`
	Order int    `json:"order" binding:"omitempty,gte=0"`

	Hidden    bool `json:"hidden"`
	Disabled  bool `json:"disabled"`
	Published bool `json:"published"`

	AnyOfPermissions []string `json:"any_of_permissions,omitempty"`
	AllOfPermissions []string `json:"all_of_permissions,omitempty"`
}

// SyncMenuItemsRequest 定义批量同步菜单的请求体。
type SyncMenuItemsRequest struct {
	Items           []SyncMenuItemRequest `json:"items" binding:"required"`
	Upsert          bool                  `json:"upsert"`
	SyncPermissions bool                  `json:"sync_permissions"`
}

// SyncMenuSkippedItem 记录同步过程中被跳过的菜单项。
type SyncMenuSkippedItem struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// SyncMenuItemsResult 汇总菜单同步的创建、更新与跳过结果。
type SyncMenuItemsResult struct {
	Created []string              `json:"created"`
	Updated []string              `json:"updated"`
	Skipped []SyncMenuSkippedItem `json:"skipped"`
}

// CreateMenuItem 创建一条新的菜单定义。
func (s *MenuService) CreateMenuItem(ctx context.Context, req *CreateMenuItemRequest) (*iamentity.MenuItem, error) {
	if req == nil {
		return nil, errorx.New(errorx.Validation, "request is required")
	}
	item := &iamentity.MenuItem{
		Code:      req.Code,
		ParentID:  req.ParentID,
		Title:     req.Title,
		Path:      req.Path,
		Icon:      req.Icon,
		Type:      req.Type,
		Order:     req.Order,
		Route:     req.Route,
		Component: req.Component,

		Hidden:    req.Hidden,
		Disabled:  req.Disabled,
		Published: req.Published,

		AnyOfPermissions: iamentity.StringArray(req.AnyOfPermissions),
		AllOfPermissions: iamentity.StringArray(req.AllOfPermissions),
	}
	if err := s.createMenuWithAuthorization(ctx, item); err != nil {
		return nil, err
	}
	s.logger.Info(ctx, "[MenuService] create menu",
		logging.Int64("menu_id", item.GetID()),
		logging.String("code", item.Code),
		logging.String("title", item.Title),
	)
	return item, nil
}

// UpdateMenuItem 按 ID 更新菜单定义。
func (s *MenuService) UpdateMenuItem(
	ctx context.Context,
	id int64,
	req *UpdateMenuItemRequest,
	patches ...svc.FieldPatch[iamentity.MenuItem],
) (*iamentity.MenuItem, error) {
	if req == nil {
		return nil, errorx.New(errorx.Validation, "update menu item request is required")
	}
	item, err := s.menuRepo.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	if req.Title != "" {
		item.Title = req.Title
	}
	if req.Path != nil {
		item.Path = *req.Path
	}
	if req.Icon != nil {
		item.Icon = *req.Icon
	}
	if req.Type != "" {
		item.Type = req.Type
	}
	if req.Order != nil {
		item.Order = *req.Order
	}
	if req.Route != nil {
		item.Route = *req.Route
	}
	if req.Component != nil {
		item.Component = *req.Component
	}
	if req.Hidden != nil {
		item.Hidden = *req.Hidden
	}
	if req.Disabled != nil {
		item.Disabled = *req.Disabled
	}
	if req.Published != nil {
		item.Published = *req.Published
	}
	if req.AnyOfPermissions != nil {
		item.AnyOfPermissions = iamentity.StringArray(req.AnyOfPermissions)
	}
	if req.AllOfPermissions != nil {
		item.AllOfPermissions = iamentity.StringArray(req.AllOfPermissions)
	}
	if err := svc.ApplyFieldPatches(item, patches...); err != nil {
		return nil, err
	}

	if err := s.updateMenuWithAuthorization(ctx, svc.MenuPermissionSet.Code(iammw.ActionWrite), item); err != nil {
		return nil, err
	}
	s.logger.Info(ctx, "[MenuService] update menu",
		logging.Int64("menu_id", item.GetID()),
		logging.String("code", item.Code),
	)
	return item, nil
}

// SyncMenuItems 按声明式菜单定义批量同步菜单数据。
func (s *MenuService) SyncMenuItems(ctx context.Context, req *SyncMenuItemsRequest) (*SyncMenuItemsResult, error) {
	if req == nil {
		return nil, errorx.New(errorx.Validation, "request is required")
	}
	if len(req.Items) == 0 {
		return nil, errorx.New(errorx.Validation, "items is required")
	}

	result := &SyncMenuItemsResult{
		Created: make([]string, 0, len(req.Items)),
		Updated: make([]string, 0, len(req.Items)),
		Skipped: make([]SyncMenuSkippedItem, 0),
	}

	// 1. 准备 code 索引并完成权限、重复项、自引用等基础校验。
	itemsByCode := make(map[string]SyncMenuItemRequest, len(req.Items))
	for _, raw := range req.Items {
		if err := validateMenuPermissionCodes(raw.AnyOfPermissions, raw.AllOfPermissions); err != nil {
			return nil, err
		}
		if _, exists := itemsByCode[raw.Code]; exists {
			return nil, errorx.New(errorx.Validation, "同步菜单中存在重复 code: "+raw.Code)
		}
		if raw.ParentCode != "" && raw.ParentCode == raw.Code {
			return nil, errorx.New(errorx.Validation, "menu parent_code 不能指向自身: "+raw.Code)
		}
		itemsByCode[raw.Code] = raw
	}

	if err := s.validateSyncMenuParentCodes(ctx, itemsByCode); err != nil {
		return nil, err
	}

	// 2. 预加载/创建本批次菜单，确保后续解析 parent_code 时能拿到最新节点集合。
	stagedItems := make(map[string]*iamentity.MenuItem, len(req.Items))
	for _, raw := range req.Items {

		existing, err := s.menuRepo.FindByCodeWithDeleted(ctx, raw.Code)
		if err != nil && !errorx.Is(err, errorx.NotFound) {
			return nil, err
		}

		if existing == nil || errorx.Is(err, errorx.NotFound) {
			item := &iamentity.MenuItem{
				Code:             raw.Code,
				Title:            raw.Title,
				Path:             raw.Path,
				Icon:             raw.Icon,
				Type:             raw.Type,
				Order:            raw.Order,
				Hidden:           raw.Hidden,
				Disabled:         raw.Disabled,
				Published:        raw.Published,
				AnyOfPermissions: iamentity.StringArray(raw.AnyOfPermissions),
				AllOfPermissions: iamentity.StringArray(raw.AllOfPermissions),
			}
			item.SetUpdatedAt(time.Now())
			if err := item.Validate(); err != nil {
				return nil, err
			}
			if err := s.createMenuWithAuthorization(ctx, item); err != nil {
				return nil, err
			}
			stagedItems[item.Code] = item
			result.Created = append(result.Created, item.Code)
			continue
		}

		if existing.DeletedAt != nil {
			result.Skipped = append(result.Skipped, SyncMenuSkippedItem{
				Code:   raw.Code,
				Reason: "菜单已软删除，请先恢复后再同步",
			})
			continue
		}

		stagedItems[existing.Code] = existing
	}

	// 3. 二次遍历做字段同步、父子关系解析和最终持久化。
	for _, raw := range req.Items {
		item := stagedItems[raw.Code]
		if item == nil {
			continue
		}
		created := contains(result.Created, raw.Code)

		dirty := false
		if req.Upsert {
			dirty = syncMenuBaseFields(item, raw) || dirty
		}
		if req.SyncPermissions {
			if !stringSliceEquals([]string(item.AnyOfPermissions), raw.AnyOfPermissions) {
				item.AnyOfPermissions = iamentity.StringArray(raw.AnyOfPermissions)
				dirty = true
			}
			if !stringSliceEquals([]string(item.AllOfPermissions), raw.AllOfPermissions) {
				item.AllOfPermissions = iamentity.StringArray(raw.AllOfPermissions)
				dirty = true
			}
		}
		parentID, err := s.resolveSyncMenuParentID(ctx, raw.ParentCode, stagedItems)
		if err != nil {
			return nil, err
		}
		if !int64PtrEquals(item.ParentID, parentID) {
			item.ParentID = parentID
			dirty = true
		}

		if !dirty {
			if !created {
				result.Skipped = append(result.Skipped, SyncMenuSkippedItem{
					Code:   raw.Code,
					Reason: "无需更新",
				})
			}
			continue
		}

		item.SetUpdatedAt(time.Now())
		if err := item.Validate(); err != nil {
			return nil, err
		}
		if err := s.validateParentNoCycle(ctx, item.GetID(), item.ParentID); err != nil {
			return nil, err
		}
		if err := s.updateMenuWithAuthorization(ctx, svc.MenuPermissionSet.Code(iammw.ActionWrite), item); err != nil {
			return nil, err
		}
		if !created {
			result.Updated = append(result.Updated, item.Code)
		}
	}

	return result, nil
}

// DeleteMenuItem 软删除指定菜单。
func (s *MenuService) DeleteMenuItem(ctx context.Context, id int64) error {
	item, err := s.menuRepo.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := s.deleteMenuWithAuthorization(ctx, item); err != nil {
		return err
	}
	s.logger.Info(ctx, "[MenuService] delete menu (soft)",
		logging.Int64("menu_id", id),
		logging.String("code", item.Code),
	)
	return nil
}

// RestoreMenuItem 恢复软删的菜单。
func (s *MenuService) RestoreMenuItem(ctx context.Context, id int64) (*iamentity.MenuItem, error) {
	item, err := s.menuRepo.GetWithDeleted(ctx, id)
	if err != nil {
		return nil, err
	}
	guard, err := svc.AuthorizeWriteConstraint(ctx, s.authorizer, svc.MenuPermissionSet.Code(iammw.ActionWrite), item)
	if err != nil {
		return nil, err
	}
	item, err = s.menuRepo.RestoreByIDWithConstraint(ctx, id, guard)
	if err != nil {
		return nil, err
	}
	s.logger.Info(ctx, "[MenuService] restore menu",
		logging.Int64("menu_id", item.GetID()),
		logging.String("code", item.Code),
	)
	return item, nil
}

// PurgeMenuItem 物理删除菜单（硬删）。
func (s *MenuService) PurgeMenuItem(ctx context.Context, id int64) error {
	item, err := s.menuRepo.GetWithDeleted(ctx, id)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(ctx, s.authorizer, svc.MenuPermissionSet.Code(iammw.ActionWrite), item)
	if err != nil {
		return err
	}
	if err := s.menuRepo.PurgeByIDWithConstraint(ctx, id, guard); err != nil {
		return err
	}
	s.logger.Info(ctx, "[MenuService] purge menu (hard)",
		logging.Int64("menu_id", id),
		logging.String("code", item.Code),
	)
	return nil
}

// PublishMenuItem 切换菜单的发布状态。
func (s *MenuService) PublishMenuItem(ctx context.Context, id int64, published bool) (*iamentity.MenuItem, error) {
	item, err := s.menuRepo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	item.Published = published
	item.SetUpdatedAt(time.Now())
	if err := s.updateMenuWithAuthorization(ctx, svc.MenuPermissionSet.Code(iammw.ActionPublish), item); err != nil {
		return nil, err
	}
	s.logger.Info(ctx, "[MenuService] publish menu",
		logging.Int64("menu_id", item.GetID()),
		logging.String("code", item.Code),
		logging.Bool("published", published),
	)
	return item, nil
}

// ListMenuItems 返回全部菜单定义。
func (s *MenuService) ListMenuItems(ctx context.Context) ([]*iamentity.MenuItem, error) {
	if err := s.authorizePlatform(ctx, svc.MenuPermissionSet.Code(iammw.ActionRead), &iamentity.MenuItem{}); err != nil {
		return nil, err
	}
	return s.menuRepo.ListAll(ctx)
}

// CreateEntity 创建菜单实体；用于标准 CRUD application 路径，不隐式做额外鉴权。
func (s *MenuService) CreateEntity(ctx context.Context, item *iamentity.MenuItem) error {
	if err := validateDirectMenuCreatePayload(item); err != nil {
		return err
	}
	return s.createMenu(ctx, item)
}

// CreateEntityWithConstraint 在显式 guard 下创建菜单实体。
func (s *MenuService) CreateEntityWithConstraint(
	ctx context.Context,
	item *iamentity.MenuItem,
	guard svc.WriteConstraint,
) error {
	if err := validateDirectMenuCreatePayload(item); err != nil {
		return err
	}
	return s.createMenuWithConstraint(ctx, item, guard)
}

// UpdateEntity 更新菜单实体；用于标准 CRUD application 路径，不隐式做额外鉴权。
func (s *MenuService) UpdateEntity(ctx context.Context, item *iamentity.MenuItem) error {
	if item == nil {
		return errorx.New(errorx.Validation, "menu item is required")
	}
	current, err := s.menuRepo.Get(ctx, item.GetID())
	if err != nil {
		return err
	}
	if err := validateDirectMenuUpdatePayload(current, item); err != nil {
		return err
	}
	normalizeDirectMenuUpdate(current, item)
	return s.updateMenu(ctx, item)
}

// UpdateEntityWithConstraint 在显式 guard 下更新菜单实体。
func (s *MenuService) UpdateEntityWithConstraint(
	ctx context.Context,
	item *iamentity.MenuItem,
	guard svc.WriteConstraint,
) error {
	if item == nil {
		return errorx.New(errorx.Validation, "menu item is required")
	}
	current, err := s.menuRepo.Get(ctx, item.GetID())
	if err != nil {
		return err
	}
	if err := validateDirectMenuUpdatePayload(current, item); err != nil {
		return err
	}
	normalizeDirectMenuUpdate(current, item)
	return s.updateMenuWithConstraint(ctx, item, guard)
}

// DeleteEntity 删除菜单实体；用于标准 CRUD application 路径，不隐式做额外鉴权。
func (s *MenuService) DeleteEntity(ctx context.Context, id int64) error {
	item, err := s.menuRepo.Get(ctx, id)
	if err != nil {
		return err
	}
	return s.deleteMenu(ctx, item)
}

// DeleteEntityWithConstraint 在显式 guard 下删除菜单实体。
func (s *MenuService) DeleteEntityWithConstraint(ctx context.Context, id int64, guard svc.WriteConstraint) error {
	item, err := s.menuRepo.Get(ctx, id)
	if err != nil {
		return err
	}
	return s.deleteMenuWithConstraint(ctx, item, guard)
}

func (s *MenuService) authorizePlatform(ctx context.Context, permission string, targets ...any) error {
	if s.authorizer == nil {
		return errorx.New(errorx.InvalidInput, "authorizer is required")
	}
	return s.authorizer.Require(ctx, permission, targets...)
}

func (s *MenuService) createMenu(ctx context.Context, item *iamentity.MenuItem) error {
	if err := s.validateMenuForCreate(ctx, item); err != nil {
		return err
	}
	if err := s.menuRepo.Create(ctx, item); err != nil {
		return errorx.Wrap(err, errorx.Database, "创建菜单失败")
	}
	return nil
}

func (s *MenuService) createMenuWithConstraint(ctx context.Context, item *iamentity.MenuItem, guard svc.WriteConstraint) error {
	if err := s.validateMenuForCreate(ctx, item); err != nil {
		return err
	}
	if err := s.menuRepo.CreateWithConstraint(ctx, item, guard); err != nil {
		return errorx.Wrap(err, errorx.Database, "创建菜单失败")
	}
	return nil
}

func (s *MenuService) createMenuWithAuthorization(ctx context.Context, item *iamentity.MenuItem) error {
	guard, err := svc.AuthorizeWriteConstraint(ctx, s.authorizer, svc.MenuPermissionSet.Code(iammw.ActionWrite), item)
	if err != nil {
		return err
	}
	return s.createMenuWithConstraint(ctx, item, guard)
}

func (s *MenuService) updateMenu(ctx context.Context, item *iamentity.MenuItem) error {
	if err := s.validateMenuForUpdate(ctx, item); err != nil {
		return err
	}
	if err := s.menuRepo.Update(ctx, item); err != nil {
		return errorx.Wrap(err, errorx.Database, "更新菜单失败")
	}
	return nil
}

func (s *MenuService) updateMenuWithConstraint(ctx context.Context, item *iamentity.MenuItem, guard svc.WriteConstraint) error {
	if err := s.validateMenuForUpdate(ctx, item); err != nil {
		return err
	}
	if err := s.menuRepo.UpdateWithConstraint(ctx, item, guard); err != nil {
		return errorx.Wrap(err, errorx.Database, "更新菜单失败")
	}
	return nil
}

func (s *MenuService) updateMenuWithAuthorization(ctx context.Context, permission string, item *iamentity.MenuItem) error {
	guard, err := svc.AuthorizeWriteConstraint(ctx, s.authorizer, permission, item)
	if err != nil {
		return err
	}
	return s.updateMenuWithConstraint(ctx, item, guard)
}

func (s *MenuService) deleteMenu(ctx context.Context, item *iamentity.MenuItem) error {
	return s.menuRepo.Delete(ctx, item.GetID())
}

func (s *MenuService) deleteMenuWithConstraint(ctx context.Context, item *iamentity.MenuItem, guard svc.WriteConstraint) error {
	return s.menuRepo.DeleteWithConstraint(ctx, item.GetID(), guard)
}

func (s *MenuService) deleteMenuWithAuthorization(ctx context.Context, item *iamentity.MenuItem) error {
	guard, err := svc.AuthorizeWriteConstraint(ctx, s.authorizer, svc.MenuPermissionSet.Code(iammw.ActionWrite), item)
	if err != nil {
		return err
	}
	return s.deleteMenuWithConstraint(ctx, item, guard)
}

func (s *MenuService) validateMenuForCreate(ctx context.Context, item *iamentity.MenuItem) error {
	if item == nil {
		return errorx.New(errorx.Validation, "menu item is required")
	}
	item.SetUpdatedAt(time.Now())
	if err := item.Validate(); err != nil {
		return err
	}
	if err := s.validateParentNoCycle(ctx, 0, item.ParentID); err != nil {
		return err
	}
	if err := validateMenuPermissionCodes([]string(item.AnyOfPermissions), []string(item.AllOfPermissions)); err != nil {
		return err
	}

	// menu_items.code 是唯一索引，且 Delete 为软删：
	// 这里显式检查并返回更友好的错误信息（当前策略：code 不可复用）。
	if existing, err := s.menuRepo.FindByCodeWithDeleted(ctx, item.Code); err == nil && existing != nil {
		if existing.DeletedAt != nil {
			return errorx.New(errorx.Validation, "菜单 code 已被占用（已删除），当前策略不允许复用；请更换 code 或进行物理删除后重建")
		}
		return errorx.New(errorx.Validation, "菜单 code 已存在")
	} else if err != nil && !errorx.Is(err, errorx.NotFound) {
		return err
	}
	return nil
}

func (s *MenuService) validateMenuForUpdate(ctx context.Context, item *iamentity.MenuItem) error {
	if item == nil {
		return errorx.New(errorx.Validation, "menu item is required")
	}
	item.SetUpdatedAt(time.Now())
	if err := item.Validate(); err != nil {
		return err
	}
	if err := validateMenuPermissionCodes([]string(item.AnyOfPermissions), []string(item.AllOfPermissions)); err != nil {
		return err
	}
	if err := s.validateParentNoCycle(ctx, item.GetID(), item.ParentID); err != nil {
		return err
	}
	return nil
}

func validateDirectMenuCreatePayload(item *iamentity.MenuItem) error {
	if item == nil {
		return errorx.New(errorx.Validation, "menu item is required")
	}
	if item.GetID() != 0 || item.Version != 0 || !item.CreatedAt.IsZero() || !item.UpdatedAt.IsZero() || item.DeletedAt != nil {
		return errorx.New(errorx.Validation, "create menu payload contains managed fields")
	}
	return nil
}

func validateDirectMenuUpdatePayload(current *iamentity.MenuItem, item *iamentity.MenuItem) error {
	if current == nil || item == nil {
		return errorx.New(errorx.Validation, "menu item is required")
	}
	if item.GetID() != current.GetID() {
		return errorx.New(errorx.Validation, "menu id mismatch")
	}
	if item.Code != current.Code ||
		item.Version != current.Version ||
		!item.CreatedAt.Equal(current.CreatedAt) ||
		!item.UpdatedAt.Equal(current.UpdatedAt) ||
		!timePtrEqual(item.DeletedAt, current.DeletedAt) {
		return errorx.New(errorx.Validation, "update menu payload contains immutable or managed fields")
	}
	return nil
}

func normalizeDirectMenuUpdate(current *iamentity.MenuItem, item *iamentity.MenuItem) {
	item.Code = current.Code
	item.Version = current.Version
	item.CreatedAt = current.CreatedAt
	item.UpdatedAt = current.UpdatedAt
	item.DeletedAt = current.DeletedAt
}

func timePtrEqual(left *time.Time, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

// MenuNode 表示前端菜单树节点。
type MenuNode struct {
	ID       int64  `json:"id"`
	Code     string `json:"code"`
	ParentID *int64 `json:"parent_id,omitempty"`

	Title     string `json:"title"`
	Path      string `json:"path,omitempty"`
	Icon      string `json:"icon,omitempty"`
	Type      string `json:"type"`
	Order     int    `json:"order"`
	Route     string `json:"route,omitempty"`
	Component string `json:"component,omitempty"`

	Hidden    bool `json:"hidden"`
	Disabled  bool `json:"disabled"`
	Published bool `json:"published"`

	AnyOfPermissions []string `json:"any_of_permissions,omitempty"`
	AllOfPermissions []string `json:"all_of_permissions,omitempty"`

	Children []*MenuNode `json:"children,omitempty"`
}

// MyMenuTree 返回当前用户可见的菜单树（按权限过滤）。
func (s *MenuService) MyMenuTree(ctx context.Context, reqCtx httpx.IRequestContext) ([]*MenuNode, error) {
	items, err := s.menuRepo.ListPublished(ctx)
	if err != nil {
		return nil, err
	}
	return buildMenuTree(items, reqCtx), nil
}

// validateParentNoCycle 校验 parent_id 不会形成菜单环。
func (s *MenuService) validateParentNoCycle(ctx context.Context, selfID int64, parentID *int64) error {
	if parentID == nil {
		return nil
	}
	if *parentID <= 0 {
		return errorx.New(errorx.Validation, "parent_id 无效")
	}
	if selfID > 0 && *parentID == selfID {
		return errorx.New(errorx.Validation, "parent_id 不能指向自身")
	}

	visited := map[int64]struct{}{}
	if selfID > 0 {
		visited[selfID] = struct{}{}
	}

	curID := *parentID
	for curID > 0 {
		if _, ok := visited[curID]; ok {
			return errorx.New(errorx.Validation, "菜单 parent 链路存在环")
		}
		visited[curID] = struct{}{}

		cur, err := s.menuRepo.Get(ctx, curID)
		if err != nil {
			return err
		}
		if cur.ParentID == nil {
			break
		}
		curID = *cur.ParentID
	}
	return nil
}

// validateMenuPermissionCodes 校验菜单上声明的权限编码是否合法且已注册。
func validateMenuPermissionCodes(anyOf []string, allOf []string) error {
	if err := iammw.EnsureStrictPermissionRegistryLoaded(); err != nil {
		return err
	}
	for _, p := range anyOf {
		if !iammw.IsValidPermissionCode(p) {
			return errorx.New(errorx.Validation, "无效的权限: "+p)
		}
		if !iammw.HasRequiredPermission(p) {
			return errorx.New(errorx.Validation, "未知权限: "+p)
		}
	}
	for _, p := range allOf {
		if !iammw.IsValidPermissionCode(p) {
			return errorx.New(errorx.Validation, "无效的权限: "+p)
		}
		if !iammw.HasRequiredPermission(p) {
			return errorx.New(errorx.Validation, "未知权限: "+p)
		}
	}
	return nil
}

// validateSyncMenuParentCodes 校验同步请求里的 parent_code 链路合法且无环。
func (s *MenuService) validateSyncMenuParentCodes(ctx context.Context, itemsByCode map[string]SyncMenuItemRequest) error {
	visiting := make(map[string]struct{}, len(itemsByCode))
	visited := make(map[string]struct{}, len(itemsByCode))

	// 1. 先校验所有 parent_code 是否存在，并拒绝直接指向自身。
	for code, item := range itemsByCode {
		if item.ParentCode == "" {
			continue
		}
		if _, ok := itemsByCode[item.ParentCode]; ok {
			continue
		}
		if _, err := s.menuRepo.FindByCode(ctx, item.ParentCode); err != nil {
			if errorx.Is(err, errorx.NotFound) {
				return errorx.New(errorx.Validation, "menu parent_code 不存在: "+item.ParentCode)
			}
			return err
		}
		if item.ParentCode == code {
			return errorx.New(errorx.Validation, "menu parent_code 不能指向自身: "+code)
		}
	}

	var walk func(code string) error
	walk = func(code string) error {
		if _, ok := visited[code]; ok {
			return nil
		}
		if _, ok := visiting[code]; ok {
			return errorx.New(errorx.Validation, "同步菜单 parent_code 链路存在环")
		}

		visiting[code] = struct{}{}
		parentCode := itemsByCode[code].ParentCode
		if parentCode != "" {
			if _, ok := itemsByCode[parentCode]; ok {
				if err := walk(parentCode); err != nil {
					return err
				}
			}
		}

		delete(visiting, code)
		visited[code] = struct{}{}
		return nil
	}

	// 2. 再用 DFS 检查批次内 parent_code 是否形成环。
	for code := range itemsByCode {
		if err := walk(code); err != nil {
			return err
		}
	}

	return nil
}

// resolveSyncMenuParentID 解析Sync菜单父级ID。
func (s *MenuService) resolveSyncMenuParentID(
	ctx context.Context,
	parentCode string,
	stagedItems map[string]*iamentity.MenuItem,
) (*int64, error) {
	if parentCode == "" {
		return nil, nil
	}
	if parent, ok := stagedItems[parentCode]; ok && parent != nil {
		parentID := parent.GetID()
		return &parentID, nil
	}

	parent, err := s.menuRepo.FindByCode(ctx, parentCode)
	if err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.Validation, "menu parent_code 不存在: "+parentCode)
		}
		return nil, err
	}

	parentID := parent.GetID()
	return &parentID, nil
}

// syncMenuBaseFields 同步菜单基础字段集合。
func syncMenuBaseFields(item *iamentity.MenuItem, req SyncMenuItemRequest) bool {
	if item == nil {
		return false
	}

	dirty := false
	if item.Title != req.Title {
		item.Title = req.Title
		dirty = true
	}
	if item.Path != req.Path {
		item.Path = req.Path
		dirty = true
	}
	if item.Icon != req.Icon {
		item.Icon = req.Icon
		dirty = true
	}
	if item.Type != req.Type && req.Type != "" {
		item.Type = req.Type
		dirty = true
	}
	if item.Order != req.Order {
		item.Order = req.Order
		dirty = true
	}
	if item.Hidden != req.Hidden {
		item.Hidden = req.Hidden
		dirty = true
	}
	if item.Disabled != req.Disabled {
		item.Disabled = req.Disabled
		dirty = true
	}
	if item.Published != req.Published {
		item.Published = req.Published
		dirty = true
	}

	return dirty
}

// stringSliceEquals 判断两个字符串切片是否完全相等。
func stringSliceEquals(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// int64PtrEquals 判断两个 int64 指针是否都为空或值相等。
func int64PtrEquals(left *int64, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

// contains 判断目标字符串是否已存在于结果切片中。
func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

// buildMenuTree 把扁平菜单列表构造成已排序、按权限过滤后的树结构。
func buildMenuTree(items []*iamentity.MenuItem, reqCtx httpx.IRequestContext) []*MenuNode {
	// 1. 先把扁平菜单实体转换成节点映射。
	nodes := make(map[int64]*MenuNode, len(items))
	for i := range items {
		nodes[items[i].ID] = toNode(items[i])
	}

	// 2. 再按 ParentID 组装树结构；缺失父节点的项会提升为根节点。
	var roots []*MenuNode
	for _, n := range nodes {
		if n.ParentID == nil {
			roots = append(roots, n)
			continue
		}
		parent, ok := nodes[*n.ParentID]
		if !ok {
			roots = append(roots, n)
			continue
		}
		parent.Children = append(parent.Children, n)
	}

	// 3. 最后统一排序并按权限过滤不可见节点。
	sortMenuTree(roots)
	roots = filterMenuTree(roots, reqCtx)
	return roots
}

// toNode 把菜单实体转换成菜单树节点。
func toNode(item *iamentity.MenuItem) *MenuNode {
	if item == nil {
		return nil
	}
	var parentID *int64
	if item.ParentID != nil {
		v := *item.ParentID
		parentID = &v
	}

	return &MenuNode{
		ID:               item.ID,
		Code:             item.Code,
		ParentID:         parentID,
		Title:            item.Title,
		Path:             item.Path,
		Icon:             item.Icon,
		Type:             item.Type,
		Order:            item.Order,
		Route:            item.Route,
		Component:        item.Component,
		Hidden:           item.Hidden,
		Disabled:         item.Disabled,
		Published:        item.Published,
		AnyOfPermissions: append([]string(nil), item.AnyOfPermissions...),
		AllOfPermissions: append([]string(nil), item.AllOfPermissions...),
	}
}

// sortMenuTree 对整棵菜单树做稳定排序。
func sortMenuTree(nodes []*MenuNode) {
	visited := map[int64]struct{}{}
	sortMenuTreeRec(nodes, visited)
}

// sortMenuTreeRec 递归按 order/title 对菜单节点排序。
func sortMenuTreeRec(nodes []*MenuNode, visited map[int64]struct{}) {
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Order != nodes[j].Order {
			return nodes[i].Order < nodes[j].Order
		}
		return nodes[i].Title < nodes[j].Title
	})
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if _, ok := visited[n.ID]; ok {
			continue
		}
		visited[n.ID] = struct{}{}
		if len(n.Children) > 0 {
			sortMenuTreeRec(n.Children, visited)
		}
	}
}

// filterMenuTree 过滤整棵菜单树中当前请求不可见的节点。
func filterMenuTree(nodes []*MenuNode, reqCtx httpx.IRequestContext) []*MenuNode {
	visited := map[int64]struct{}{}
	return filterMenuTreeRec(nodes, reqCtx, visited)
}

// filterMenuTreeRec 递归过滤菜单树，并保留仍有可见子节点的父菜单。
func filterMenuTreeRec(nodes []*MenuNode, reqCtx httpx.IRequestContext, visited map[int64]struct{}) []*MenuNode {
	out := make([]*MenuNode, 0, len(nodes))
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if _, ok := visited[n.ID]; ok {
			// 防御：出现环/重复引用时直接丢弃，避免递归栈溢出。
			continue
		}
		visited[n.ID] = struct{}{}
		if n.Disabled || n.Hidden {
			continue
		}

		// 1. 先递归处理子节点，避免父节点权限通过但子节点仍带脏数据。
		n.Children = filterMenuTreeRec(n.Children, reqCtx, visited)

		// 2. 再计算当前节点可见性；父节点即使自身不可见，只要仍有可见子节点也要保留。
		selfVisible := evaluateMenuVisibility(n, reqCtx)
		if selfVisible || len(n.Children) > 0 {
			out = append(out, n)
		}
	}
	return out
}

// evaluateMenuVisibility 判断单个菜单节点在当前请求上下文中是否可见。
func evaluateMenuVisibility(n *MenuNode, reqCtx httpx.IRequestContext) bool {
	// 没有上下文时：仅显示无权限约束的菜单
	if reqCtx == nil {
		return len(n.AnyOfPermissions) == 0 && len(n.AllOfPermissions) == 0
	}

	// all_of_permissions：必须全部满足
	for _, p := range n.AllOfPermissions {
		if !iammw.HasPermission(reqCtx, p) {
			return false
		}
	}
	// any_of_permissions：至少一个满足
	if len(n.AnyOfPermissions) > 0 {
		for _, p := range n.AnyOfPermissions {
			if iammw.HasPermission(reqCtx, p) {
				return true
			}
		}
		return false
	}
	return true
}
