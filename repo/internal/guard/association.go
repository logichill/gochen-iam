package guard

import (
	"context"
	"sort"
	"strconv"
	"strings"

	iamaccess "gochen-iam/access"
	"gochen/db/orm"
	"gochen/errors"
)

type transactionRunner interface {
	WithinTx(context.Context, func(context.Context) error) error
}

// 只声明锁定所需字段，避免空更新触发 ORM 的自动更新时间戳或关联保存。
type associationResource struct {
	ID      int64
	Version uint64
}

// MutatePair 将资源约束校验和关联修改放在同一事务内。
// 条件更新同时取得资源行的写锁，避免校验后资源被迁移、删除或修改。
func MutatePair(ctx context.Context, runner transactionRunner, constraint iamaccess.WriteConstraint,
	ownerKind string, ownerID int64, relatedKind string, relatedID int64, mutate func(context.Context) error,
) error {
	owner, related, err := RequirePair(constraint, ownerKind, ownerID, relatedKind, relatedID)
	if err != nil {
		return err
	}
	resources := []iamaccess.ResourceConstraint{owner, related}
	// 用户/角色/组织均有双向操作入口，固定锁顺序防止互相等待。
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].Kind != resources[j].Kind {
			return resources[i].Kind < resources[j].Kind
		}
		return resources[i].ResourceID < resources[j].ResourceID
	})
	return runner.WithinTx(ctx, func(txCtx context.Context) error {
		session, ok := orm.SessionFromContext(txCtx)
		if !ok || session == nil {
			return errors.NewCode(errors.Internal, "association mutation requires a transaction")
		}
		for _, resource := range resources {
			if err := lockResourceRevision(txCtx, session, resource); err != nil {
				return err
			}
		}
		return mutate(txCtx)
	})
}

func lockResourceRevision(ctx context.Context, session orm.IOrmSession, resource iamaccess.ResourceConstraint) error {
	if resource.ResourceID == "" || strings.TrimSpace(resource.TenantID) == "" || (resource.ManagedScopeID <= 0 && !resource.GlobalScope) {
		return errors.NewCode(errors.Forbidden, "association constraint requires resource id, tenant and scope")
	}
	version, err := strconv.ParseUint(resource.Revision, 10, 64)
	if err != nil {
		return errors.NewCode(errors.InvalidInput, "association constraint revision is invalid")
	}
	meta := orm.ModelMeta{ModelFactory: orm.NewModelFactory[associationResource]()}
	scopeColumn := "managed_scope_id"
	switch resource.Kind {
	case "iam.user":
		meta.Table = "users"
	case "iam.group":
		meta.Table = "groups"
	case "iam.role":
		meta.Table = "roles"
		scopeColumn = "namespace_scope_id"
	default:
		return errors.NewCode(errors.InvalidInput, "unsupported association resource kind")
	}
	model, err := session.Model(&meta)
	if err != nil {
		return err
	}
	writer, ok := model.(orm.IModelWithResult)
	if !ok {
		return errors.NewCode(errors.Unsupported, "association constraints require write results")
	}
	filters := []orm.QueryOption{orm.WithWhere("id = ? AND tenant_id = ? AND version = ? AND deleted_at IS NULL", resource.ResourceID, resource.TenantID, version)}
	if !resource.GlobalScope {
		filters = append(filters, orm.WithWhere(scopeColumn+" = ?", resource.ManagedScopeID))
	}
	// 关联表写入不改变实体字段；条件空更新取得写锁而不推进实体版本。
	result, err := writer.UpdateValuesWithResult(ctx, map[string]any{"version": version}, filters...)
	if err != nil {
		return err
	}
	if result == nil {
		return errors.NewCode(errors.Internal, "association mutation did not return a write result")
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		// MySQL 默认返回实际变更行数，匹配的空更新也是 0；在同一事务和行锁下确认命中。
		err := model.First(ctx, meta.NewModel(), append(filters, orm.WithSelect("id", "version"), orm.WithForUpdate())...)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errors.NotFound) {
			return err
		}
	}
	if affected != 1 {
		return errors.NewCode(errors.Conflict, "association resource changed after authorization").
			WithContext("resource_kind", resource.Kind).
			WithContext("resource_id", resource.ResourceID)
	}
	return nil
}
