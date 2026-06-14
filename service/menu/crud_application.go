package menu

import (
	"context"

	iamaccess "gochen-iam/access"
	iamentity "gochen-iam/entity"
	appcrud "gochen/app/crud"
	"gochen/domain/access"
	domaincrud "gochen/domain/crud"
	"gochen/errors"
)

// CRUDApplication 把 menu 的标准 CRUD 路径适配到 gochen 的统一 app/api builder。
//
// 约定：
// - 读路径继续复用通用 repo/query 能力；
// - 写路径统一委托 MenuService，避免绕过菜单自己的领域校验与 guarded write 语义。
type CRUDApplication struct {
	*appcrud.Application[*iamentity.MenuItem, int64]
	menuService *MenuService
}

// NewCRUDApplication 创建菜单 CRUD 应用适配器。
func NewCRUDApplication(
	menuRepo domaincrud.IRepository[*iamentity.MenuItem, int64],
	menuService *MenuService,
) (*CRUDApplication, error) {
	if menuService == nil {
		return nil, errors.NewCode(errors.InvalidInput, "menu service cannot be nil")
	}
	base, err := appcrud.NewApplication(menuRepo, nil, nil)
	if err != nil {
		return nil, err
	}
	return &CRUDApplication{
		Application: base,
		menuService: menuService,
	}, nil
}

// Create 创建菜单，复用 MenuService 的领域校验。
func (a *CRUDApplication) Create(ctx context.Context, entity *iamentity.MenuItem) error {
	return a.menuService.CreateEntity(ctx, entity)
}

// Update 更新菜单，复用 MenuService 的领域校验。
func (a *CRUDApplication) Update(ctx context.Context, entity *iamentity.MenuItem) error {
	return a.menuService.UpdateEntity(ctx, entity)
}

// Delete 删除菜单，复用 MenuService 的领域校验。
func (a *CRUDApplication) Delete(ctx context.Context, id int64) error {
	return a.menuService.DeleteEntity(ctx, id)
}

// ValidateWriteConstraintSupport 声明菜单 CRUD 适配器自身负责显式写约束。
func (a *CRUDApplication) ValidateWriteConstraintSupport() error {
	if a == nil || a.menuService == nil {
		return errors.NewCode(errors.InvalidInput, "menu service cannot be nil")
	}
	return nil
}

// CreateWithConstraint 在显式 guard 下创建菜单。
func (a *CRUDApplication) CreateWithConstraint(
	ctx context.Context,
	entity *iamentity.MenuItem,
	guard access.WriteConstraint,
) error {
	return a.menuService.CreateEntityWithConstraint(ctx, entity, iamaccess.NewWriteConstraint(guard, access.ConstraintMetadata{}))
}

// UpdateWithConstraint 在显式 guard 下更新菜单。
func (a *CRUDApplication) UpdateWithConstraint(
	ctx context.Context,
	entity *iamentity.MenuItem,
	guard access.WriteConstraint,
) error {
	return a.menuService.UpdateEntityWithConstraint(ctx, entity, iamaccess.NewWriteConstraint(guard, access.ConstraintMetadata{}))
}

// DeleteWithConstraint 在显式 guard 下删除菜单。
func (a *CRUDApplication) DeleteWithConstraint(
	ctx context.Context,
	id int64,
	guard access.WriteConstraint,
) error {
	return a.menuService.DeleteEntityWithConstraint(ctx, id, iamaccess.NewWriteConstraint(guard, access.ConstraintMetadata{}))
}
