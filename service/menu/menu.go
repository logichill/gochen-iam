package menu

import (
	"context"
	"sort"
	"time"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	menurepo "gochen-iam/repo/menu"
	httpx "gochen/httpx"
	"gochen/runtime/errorx"
	"gochen/runtime/logging"
)

type MenuService struct {
	menuRepo     *menurepo.MenuItemRepo
	overrideRepo *menurepo.MenuTenantOverrideRepo
	logger       logging.ILogger
}

func NewMenuService(menuRepo *menurepo.MenuItemRepo, overrideRepo *menurepo.MenuTenantOverrideRepo) *MenuService {
	return &MenuService{
		menuRepo:     menuRepo,
		overrideRepo: overrideRepo,
		logger:       logging.ComponentLogger("iam.service.menu"),
	}
}

type CreateMenuItemRequest struct {
	Code      string `json:"code"`
	ParentID  *int64 `json:"parent_id,omitempty"`
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
}

type UpdateMenuItemRequest struct {
	ParentID  *int64  `json:"parent_id,omitempty"`
	Title     string  `json:"title,omitempty"`
	Path      *string `json:"path,omitempty"`
	Icon      *string `json:"icon,omitempty"`
	Type      string  `json:"type,omitempty"`
	Order     *int    `json:"order,omitempty"`
	Route     *string `json:"route,omitempty"`
	Component *string `json:"component,omitempty"`

	Hidden    *bool `json:"hidden,omitempty"`
	Disabled  *bool `json:"disabled,omitempty"`
	Published *bool `json:"published,omitempty"`

	AnyOfPermissions []string `json:"any_of_permissions,omitempty"`
	AllOfPermissions []string `json:"all_of_permissions,omitempty"`
}

func (s *MenuService) CreateMenuItem(ctx context.Context, req *CreateMenuItemRequest) (*iamentity.MenuItem, error) {
	if req == nil {
		return nil, errorx.NewError(errorx.Validation, "request is required")
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

	if err := s.menuRepo.Create(ctx, item); err != nil {
		return nil, errorx.WrapError(err, errorx.Database, "创建菜单失败")
	}
	return item, nil
}

func (s *MenuService) UpdateMenuItem(ctx context.Context, id int64, req *UpdateMenuItemRequest) (*iamentity.MenuItem, error) {
	if req == nil {
		return nil, errorx.NewError(errorx.Validation, "request is required")
	}
	item, err := s.menuRepo.GetByID(ctx, id)
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
		return nil, errorx.WrapError(err, errorx.Database, "更新菜单失败")
	}
	return item, nil
}

func (s *MenuService) DeleteMenuItem(ctx context.Context, id int64) error {
	return s.menuRepo.Delete(ctx, id)
}

func (s *MenuService) PublishMenuItem(ctx context.Context, id int64, published bool) (*iamentity.MenuItem, error) {
	item, err := s.menuRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	item.Published = published
	item.SetUpdatedAt(time.Now())
	if err := s.menuRepo.Update(ctx, item); err != nil {
		return nil, err
	}
	return item, nil
}

func (s *MenuService) ListMenuItems(ctx context.Context) ([]*iamentity.MenuItem, error) {
	return s.menuRepo.ListAll(ctx)
}

type UpsertTenantOverrideRequest struct {
	Title     *string `json:"title,omitempty"`
	Path      *string `json:"path,omitempty"`
	Icon      *string `json:"icon,omitempty"`
	Route     *string `json:"route,omitempty"`
	Component *string `json:"component,omitempty"`
	Order     *int    `json:"order,omitempty"`
	Hidden    *bool   `json:"hidden,omitempty"`
	Disabled  *bool   `json:"disabled,omitempty"`
}

func (s *MenuService) UpsertTenantOverride(ctx context.Context, tenantID, menuCode string, req *UpsertTenantOverrideRequest) (*iamentity.MenuTenantOverride, error) {
	if tenantID == "" {
		return nil, errorx.NewError(errorx.Validation, "tenant_id is required")
	}
	if menuCode == "" {
		return nil, errorx.NewError(errorx.Validation, "menu_code is required")
	}
	if req == nil {
		return nil, errorx.NewError(errorx.Validation, "request is required")
	}
	// 确保 menu 存在
	if _, err := s.menuRepo.GetByCode(ctx, menuCode); err != nil {
		return nil, err
	}

	o := &iamentity.MenuTenantOverride{
		TenantID:  tenantID,
		MenuCode:  menuCode,
		Title:     req.Title,
		Path:      req.Path,
		Icon:      req.Icon,
		Route:     req.Route,
		Component: req.Component,
		Order:     req.Order,
		Hidden:    req.Hidden,
		Disabled:  req.Disabled,
	}
	o.SetUpdatedAt(time.Now())
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if err := s.overrideRepo.UpsertByTenantAndMenuCode(ctx, o); err != nil {
		return nil, err
	}
	return s.overrideRepo.GetByTenantAndMenuCode(ctx, tenantID, menuCode)
}

func (s *MenuService) ListTenantOverrides(ctx context.Context, tenantID string) ([]*iamentity.MenuTenantOverride, error) {
	return s.overrideRepo.ListByTenant(ctx, tenantID)
}

func (s *MenuService) DeleteTenantOverride(ctx context.Context, tenantID, menuCode string) error {
	return s.overrideRepo.DeleteByTenantAndMenuCode(ctx, tenantID, menuCode)
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

// GetMyMenuTree 返回当前用户可见的菜单树（按 tenant override + 权限过滤）。
func (s *MenuService) GetMyMenuTree(ctx context.Context, reqCtx httpx.IRequestContext) ([]*MenuNode, error) {
	items, err := s.menuRepo.ListPublished(ctx)
	if err != nil {
		return nil, err
	}

	tenantID := ""
	if reqCtx != nil {
		tenantID = reqCtx.GetTenantID()
	}
	var overrides []*iamentity.MenuTenantOverride
	if tenantID != "" {
		overrides, err = s.overrideRepo.ListByTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
	}

	return buildMenuTree(items, overrides, reqCtx), nil
}

func (s *MenuService) validateParentNoCycle(ctx context.Context, selfID int64, parentID *int64) error {
	if parentID == nil {
		return nil
	}
	if *parentID <= 0 {
		return errorx.NewError(errorx.Validation, "parent_id 无效")
	}
	if selfID > 0 && *parentID == selfID {
		return errorx.NewError(errorx.Validation, "parent_id 不能指向自身")
	}

	visited := map[int64]struct{}{}
	if selfID > 0 {
		visited[selfID] = struct{}{}
	}

	curID := *parentID
	for curID > 0 {
		if _, ok := visited[curID]; ok {
			return errorx.NewError(errorx.Validation, "菜单 parent 链路存在环")
		}
		visited[curID] = struct{}{}

		cur, err := s.menuRepo.GetByID(ctx, curID)
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
	for _, p := range anyOf {
		if !iammw.IsValidPermissionCode(p) {
			return errorx.NewError(errorx.Validation, "无效的权限: "+p)
		}
	}
	for _, p := range allOf {
		if !iammw.IsValidPermissionCode(p) {
			return errorx.NewError(errorx.Validation, "无效的权限: "+p)
		}
	}
	return nil
}

func buildMenuTree(items []*iamentity.MenuItem, overrides []*iamentity.MenuTenantOverride, reqCtx httpx.IRequestContext) []*MenuNode {
	overrideByCode := make(map[string]*iamentity.MenuTenantOverride, len(overrides))
	for i := range overrides {
		overrideByCode[overrides[i].MenuCode] = overrides[i]
	}

	nodes := make(map[int64]*MenuNode, len(items))
	for i := range items {
		item := applyOverride(items[i], overrideByCode[items[i].Code])
		nodes[item.ID] = toNode(item)
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

func applyOverride(item *iamentity.MenuItem, o *iamentity.MenuTenantOverride) *iamentity.MenuItem {
	if item == nil || o == nil {
		return item
	}
	clone := *item
	if o.Title != nil {
		clone.Title = *o.Title
	}
	if o.Path != nil {
		clone.Path = *o.Path
	}
	if o.Icon != nil {
		clone.Icon = *o.Icon
	}
	if o.Route != nil {
		clone.Route = *o.Route
	}
	if o.Component != nil {
		clone.Component = *o.Component
	}
	if o.Order != nil {
		clone.Order = *o.Order
	}
	if o.Hidden != nil {
		clone.Hidden = *o.Hidden
	}
	if o.Disabled != nil {
		clone.Disabled = *o.Disabled
	}
	return &clone
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
