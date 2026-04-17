package middleware

import (
	"context"
)

type fixedAuthContextResolver struct {
	kind string
}

func (r fixedAuthContextResolver) ResolveAuthContext(_ context.Context, claims *JWTClaims) (*ResolvedAuthContext, error) {
	if claims == nil {
		return &ResolvedAuthContext{}, nil
	}
	kind := r.kind
	if kind == "" {
		kind = "tenant"
	}
	return &ResolvedAuthContext{
		ActiveScopeID:   claims.ActiveScopeID,
		ActiveScopeKind: kind,
		VisibleScopeIDs: []int64{claims.ActiveScopeID},
	}, nil
}
