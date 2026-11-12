package service

import (
	"context"
	"gochen/auth"
	"gochen/domain/spec"
	"gochen/errors"
)

// DeclaredCondition executes the same frozen single-action plan used by the
// entry binding. Callers pass its result to the actual conditional repository.
func DeclaredCondition(ctx context.Context, authorizer *auth.Authorizer, ids ...string) (spec.Spec, error) {
	if ctx == nil || authorizer == nil {
		return spec.Spec{}, errors.NewCode(errors.InvalidInput, "declared execution requires context and authorizer")
	}
	plan, ok := authorizer.Plan()
	if !ok || len(plan.Descriptor.Actions) != 1 {
		return spec.Spec{}, errors.NewCode(errors.InvalidInput, "declared execution requires one frozen action")
	}
	action := plan.Descriptor.Actions[0]
	permission, _ := plan.Descriptor.PermissionFor(action.Name)
	decision, err := authorizer.Authorize(ctx, auth.Request{Resource: plan.Descriptor.Resource, Action: action.Name, Permission: permission, IDs: ids})
	if err != nil {
		return spec.Spec{}, err
	}
	if !decision.Allowed {
		return spec.Spec{}, errors.NewCode(errors.Forbidden, "declared execution denied").WithContext("reason", decision.Reason)
	}
	if len(decision.Assign) > 0 {
		return spec.Spec{}, errors.NewCode(errors.Internal, "conditional execution cannot discard assignments")
	}
	return decision.Spec, nil
}

// DeclaredExecutionBinding exposes the frozen plan executed by DeclaredCondition.
func DeclaredExecutionBinding(authorizer *auth.Authorizer, source, conditionPath string) (auth.EntryBinding, error) {
	if authorizer == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "declared execution is required")
	}
	plan, ok := authorizer.Plan()
	if !ok || len(plan.Descriptor.Actions) != 1 {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "declared execution requires one frozen action")
	}
	return auth.BindExecution(authorizer, plan.Descriptor, auth.ResourceAccessData, source, conditionPath, plan.Descriptor.Actions[0].Name)
}
