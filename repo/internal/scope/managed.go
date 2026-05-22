package scope

import (
	"context"

	iamauth "gochen-iam/auth"
	auth "gochen/auth"
	"gochen/domain/access"
)

// ResolveManagedScopeID resolves the scope used for managed-scope writes.
func ResolveManagedScopeID(ctx context.Context) int64 {
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
