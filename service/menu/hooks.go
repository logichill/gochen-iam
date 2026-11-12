package menu

import (
	"context"

	iamentity "gochen-iam/entity"
	appcrud "gochen/app/crud"
	"gochen/domain/spec"
	"gochen/errors"
)

// crudHooks 仅绑定到构造期编译的全局菜单 Application。
//
// 授权、事务与软删由 Application/仓储统一处理；这里只保留菜单自身的
// 不可变字段、父子环与权限码校验。IAM 菜单计划固定授权整个全局目录，
// 父链读取及跨软删除 code 唯一性检查在该已授权目录内执行。
func (s *MenuService) crudHooks() appcrud.Hooks[*iamentity.MenuItem] {
	return appcrud.Hooks[*iamentity.MenuItem]{
		appcrud.ActionCreate: {
			Before: func(ctx context.Context, item *iamentity.MenuItem) error {
				if err := validateDirectMenuCreatePayload(item); err != nil {
					return err
				}
				return s.validateMenuForCreate(ctx, item)
			},
		},
		appcrud.ActionUpdate: {
			Before: func(ctx context.Context, item *iamentity.MenuItem) error {
				if item == nil || item.GetID() <= 0 {
					return errors.NewCode(errors.Validation, "menu item is required")
				}
				current, err := s.menuRepo.Get(ctx, item.GetID(), spec.All())
				if err != nil {
					return err
				}
				if err := validateDirectMenuUpdatePayload(current, item); err != nil {
					return err
				}
				normalizeDirectMenuUpdate(current, item)
				return s.validateMenuForUpdate(ctx, item, spec.All())
			},
		},
	}
}
