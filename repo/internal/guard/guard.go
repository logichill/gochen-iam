package guard

import (
	"context"
	"strconv"

	iamaccess "gochen-iam/access"
	"gochen/app/access"
	"gochen/errorx"
)

func RequirePair(
	constraint iamaccess.WriteConstraint,
	ownerKind string,
	ownerID int64,
	relatedKind string,
	relatedID int64,
) (iamaccess.ResourceConstraint, iamaccess.ResourceConstraint, error) {
	owner, err := constraint.RequireResource(ownerKind, FormatInt64(ownerID))
	if err != nil {
		return iamaccess.ResourceConstraint{}, iamaccess.ResourceConstraint{}, err
	}
	related, err := constraint.RequireResource(relatedKind, FormatInt64(relatedID))
	if err != nil {
		return iamaccess.ResourceConstraint{}, iamaccess.ResourceConstraint{}, err
	}
	if err := RequireSameTenant(owner, related); err != nil {
		return iamaccess.ResourceConstraint{}, iamaccess.ResourceConstraint{}, err
	}
	return owner, related, nil
}

func RequireSameTenant(resources ...iamaccess.ResourceConstraint) error {
	if len(resources) <= 1 {
		return nil
	}
	first := resources[0].ManagedScopeID
	if first == 0 {
		return nil
	}
	for _, resource := range resources[1:] {
		if resource.ManagedScopeID != 0 && resource.ManagedScopeID != first {
			return errorx.New(errorx.Forbidden, "write constraint resources must belong to the same tenant scope")
		}
	}
	return nil
}

func FormatInt64(id int64) string {
	return strconv.FormatInt(id, 10)
}

// BindContext 将 write constraint 中的元数据与单资源 scope 边界绑定回上下文。
func BindContext(ctx context.Context, constraint iamaccess.WriteConstraint) context.Context {
	ctx = access.WithConstraintMetadata(ctx, access.ConstraintMetadata{
		DecisionID:      constraint.Metadata.DecisionID,
		SnapshotVersion: constraint.Metadata.SnapshotVersion,
		Consistency:     constraint.Metadata.Consistency,
	})
	if len(constraint.Resources) != 1 {
		return ctx
	}
	resource := constraint.Resources[0]
	if resource.ManagedScopeID == 0 {
		return ctx
	}
	return access.WithDataScope(ctx, access.DataScope{
		ActiveScopeID:   resource.ManagedScopeID,
		VisibleScopeIDs: []int64{resource.ManagedScopeID},
		Mode:            access.DataScopeModeManagedScopes,
	})
}
