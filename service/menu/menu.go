package menu

import (
	"context"
	"sort"
	"time"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	menurepo "gochen-iam/repo/menu"
	"gochen/errorx"
	"gochen/httpx"
	"gochen/logging"
)

type MenuService struct {
	menuRepo *menurepo.MenuItemRepo
	logger   logging.ILogger
}

func NewMenuService(menuRepo *menurepo.MenuItemRepo) *MenuService {
	return &MenuService{
		menuRepo: menuRepo,
		logger:   logging.ComponentLogger("iam.service.menu"),
	}
}

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

type UpdateMenuItemRequest struct {
	ParentID  *int64  `json:"parent_id,omitempty"`
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

type SyncMenuItemsRequest struct {
	Items           []SyncMenuItemRequest `json:"items" binding:"required"`
	Upsert          bool                  `json:"upsert"`
	SyncPermissions bool                  `json:"sync_permissions"`
}

type SyncMenuSkippedItem struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

type SyncMenuItemsResult struct {
	Created []string              `json:"created"`
	Updated []string              `json:"updated"`
	Skipped []SyncMenuSkippedItem `json:"skipped"`
}

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
	item.SetUpdatedAt(time.Now())
	if err := item.Validate(); err != nil {
		return nil, err
	}
	if err := s.validateParentNoCycle(ctx, 0, item.ParentID); err != nil {
		return nil, err
	}
	if err := validateMenuPermissionCodes(req.AnyOfPermissions, req.AllOfPermissions); err != nil {
		return nil, err
	}

	// menu_items.code 是唯一索引，且 Delete 为软删：
	// 这里显式检查并返回更友好的错误信息（当前策略：code 不可复用）。
	if existing, err := s.menuRepo.GetByCodeWithDeleted(ctx, item.Code); err == nil && existing != nil {
		if existing.DeletedAt != nil {
			return nil, errorx.New(errorx.Validation, "菜单 code 已被占用（已删除），当前策略不允许复用；请更换 code 或进行物理删除后重建")
		}
		return nil, errorx.New(errorx.Validation, "菜单 code 已存在")
	} else if err != nil && !errorx.Is(err, errorx.NotFound) {
		return nil, err
	}

	if err := s.menuRepo.Create(ctx, item); err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "创建菜单失败")
	}
	s.logger.Info(ctx, "[MenuService] create menu",
		logging.Int64("menu_id", item.GetID()),
		logging.String("code", item.Code),
		logging.String("title", item.Title),
	)
	return item, nil
}

func (s *MenuService) UpdateMenuItem(ctx context.Context, id int64, req *UpdateMenuItemRequest) (*iamentity.MenuItem, error) {
	if req == nil {
		return nil, errorx.New(errorx.Validation, "request is required")
	}
	item, err := s.menuRepo.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	if req.ParentID != nil {
		item.ParentID = req.ParentID
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
		if err := validateMenuPermissionCodes(req.AnyOfPermissions, nil); err != nil {
			return nil, err
		}
		item.AnyOfPermissions = iamentity.StringArray(req.AnyOfPermissions)
	}
	if req.AllOfPermissions != nil {
		if err := validateMenuPermissionCodes(nil, req.AllOfPermissions); err != nil {
			return nil, err
		}
		item.AllOfPermissions = iamentity.StringArray(req.AllOfPermissions)
	}

	item.SetUpdatedAt(time.Now())
	if err := item.Validate(); err != nil {
		return nil, err
	}
	if err := s.validateParentNoCycle(ctx, id, item.ParentID); err != nil {
		return nil, err
	}
	if err := s.menuRepo.Update(ctx, item); err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "更新菜单失败")
	}
	s.logger.Info(ctx, "[MenuService] update menu",
		logging.Int64("menu_id", item.GetID()),
		logging.String("code", item.Code),
	)
	return item, nil
}

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

	stagedItems := make(map[string]*iamentity.MenuItem, len(req.Items))
	for _, raw := range req.Items {

		existing, err := s.menuRepo.GetByCodeWithDeleted(ctx, raw.Code)
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
			if err := s.menuRepo.Create(ctx, item); err != nil {
				return nil, errorx.Wrap(err, errorx.Database, "同步菜单失败")
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
		if err := s.menuRepo.Update(ctx, item); err != nil {
			return nil, errorx.Wrap(err, errorx.Database, "同步菜单失败")
		}
		if !created {
			result.Updated = append(result.Updated, item.Code)
		}
	}

	return result, nil
}

func (s *MenuService) DeleteMenuItem(ctx context.Context, id int64) error {
	item, err := s.menuRepo.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := s.menuRepo.Delete(ctx, id); err != nil {
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
	item, err := s.menuRepo.RestoreByID(ctx, id)
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
	if err := s.menuRepo.PurgeByID(ctx, id); err != nil {
		return err
	}
	s.logger.Info(ctx, "[MenuService] purge menu (hard)",
		logging.Int64("menu_id", id),
		logging.String("code", item.Code),
	)
	return nil
}

func (s *MenuService) PublishMenuItem(ctx context.Context, id int64, published bool) (*iamentity.MenuItem, error) {
	item, err := s.menuRepo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	item.Published = published
	item.SetUpdatedAt(time.Now())
	if err := s.menuRepo.Update(ctx, item); err != nil {
		return nil, err
	}
	s.logger.Info(ctx, "[MenuService] publish menu",
		logging.Int64("menu_id", item.GetID()),
		logging.String("code", item.Code),
		logging.Bool("published", published),
	)
	return item, nil
}

func (s *MenuService) ListMenuItems(ctx context.Context) ([]*iamentity.MenuItem, error) {
	return s.menuRepo.ListAll(ctx)
}

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

// GetMyMenuTree 返回当前用户可见的菜单树（按权限过滤）。
func (s *MenuService) GetMyMenuTree(ctx context.Context, reqCtx httpx.IRequestContext) ([]*MenuNode, error) {
	items, err := s.menuRepo.ListPublished(ctx)
	if err != nil {
		return nil, err
	}
	return buildMenuTree(items, reqCtx), nil
}

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

func (s *MenuService) validateSyncMenuParentCodes(ctx context.Context, itemsByCode map[string]SyncMenuItemRequest) error {
	visiting := make(map[string]struct{}, len(itemsByCode))
	visited := make(map[string]struct{}, len(itemsByCode))

	for code, item := range itemsByCode {
		if item.ParentCode == "" {
			continue
		}
		if _, ok := itemsByCode[item.ParentCode]; ok {
			continue
		}
		if _, err := s.menuRepo.GetByCode(ctx, item.ParentCode); err != nil {
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

	for code := range itemsByCode {
		if err := walk(code); err != nil {
			return err
		}
	}

	return nil
}

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

	parent, err := s.menuRepo.GetByCode(ctx, parentCode)
	if err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.Validation, "menu parent_code 不存在: "+parentCode)
		}
		return nil, err
	}

	parentID := parent.GetID()
	return &parentID, nil
}

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

func int64PtrEquals(left *int64, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func buildMenuTree(items []*iamentity.MenuItem, reqCtx httpx.IRequestContext) []*MenuNode {
	nodes := make(map[int64]*MenuNode, len(items))
	for i := range items {
		nodes[items[i].ID] = toNode(items[i])
	}

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

	sortMenuTree(roots)
	roots = filterMenuTree(roots, reqCtx)
	return roots
}

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

func sortMenuTree(nodes []*MenuNode) {
	visited := map[int64]struct{}{}
	sortMenuTreeRec(nodes, visited)
}

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

func filterMenuTree(nodes []*MenuNode, reqCtx httpx.IRequestContext) []*MenuNode {
	visited := map[int64]struct{}{}
	return filterMenuTreeRec(nodes, reqCtx, visited)
}

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
		n.Children = filterMenuTreeRec(n.Children, reqCtx, visited)
		selfVisible := evaluateMenuVisibility(n, reqCtx)
		if selfVisible || len(n.Children) > 0 {
			out = append(out, n)
		}
	}
	return out
}

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
