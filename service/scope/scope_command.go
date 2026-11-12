package scope

import (
	"context"
	"strconv"
	"strings"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	"gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

// ScopeCommandInput carries request intent; authorization reads the actual scope tree.
type ScopeCommandInput struct {
	ID     int64
	Create *svc.CreateScopeRequest
	Update *svc.UpdateScopeRequest
}
type ScopeView struct {
	Scope      *iamentity.Scope
	Governance *svc.ScopeGovernanceState
}
type ScopeCommandResult struct {
	Scope        *iamentity.Scope
	Governance   *svc.ScopeGovernanceState
	Items        []ScopeView
	VisibleIDs   []int64
	VisibleItems []*iamentity.Scope
}
type scopeCommandInput struct {
	ScopeCommandInput
	Action string
}
type scopeCommand = app.Command[scopeCommandInput, *scopeAccess, ScopeCommandResult]

// Global reference catalogs expose existing native governance projections.
// Their source repositories retain their existing tenant predicates.
type scopeCatalogItem struct {
	ID string `entity:"id"`
}
type scopeCatalog struct {
	execution app.ExecutionDescriptor
	owner     any
}

func (r *scopeCatalog) ExecutionDescriptor() app.ExecutionDescriptor { return r.execution }

type platformScopeFact struct {
	ActiveID, RootID int64
	CoversRoot       bool
}
type scopeAccessPolicy struct {
	fact *auth.Fact[platformScopeFact]
	read bool
	http bool
}

func (p scopeAccessPolicy) Vocabulary() auth.Vocabulary { return auth.Vocabulary{} }
func (p scopeAccessPolicy) FactSources() []auth.IFactSource {
	if p.fact == nil {
		return nil
	}
	return []auth.IFactSource{p.fact}
}
func (p scopeAccessPolicy) Evaluate(ctx context.Context, req auth.Request) (auth.Decision, error) {
	principal, err := hostauthz.RequirePrincipal(ctx)
	if err != nil {
		return auth.Decision{}, err
	}
	if p.http {
		user, _ := strconv.ParseInt(principal.SubjectID, 10, 64)
		if user <= 0 {
			return auth.Decision{}, errors.NewCode(errors.Unauthorized, "用户未认证")
		}
	}
	if p.read || p.http {
		if !tenant.CurrentContext(ctx).IsSingle() && iamauth.ActiveScopeKindFromContext(ctx) != string(iamentity.ScopeTypePlatform) {
			return auth.Decision{}, errors.NewCode(errors.Forbidden, "当前授权域不是 platform")
		}
	}
	if !p.read {
		fact, err := p.fact.Get(ctx, req)
		if err != nil {
			return auth.Decision{}, err
		}
		if !fact.CoversRoot {
			return auth.Decision{}, errors.NewCode(errors.Forbidden, "当前授权域不覆盖目标资源")
		}
	}
	return auth.Decision{Allowed: true, Spec: spec.All()}, nil
}

func (s *ScopeService) compileCommands() error {
	if s.scopeRepo == nil || s.scopeRepo.Repo == nil || s.tenantRepo == nil || s.tenantRepo.Repo == nil || s.roleRepo == nil || s.roleRepo.Repo == nil || s.userRepo == nil || s.userRepo.Repo == nil || s.groupRepo == nil || s.groupRepo.Repo == nil {
		return errors.NewCode(errors.InvalidInput, "scope governance requires all actual scope and reference repositories")
	}
	metadata, err := meta.Describe[*scopeCatalogItem]()
	if err != nil {
		return err
	}
	execution, err := app.BindContract(metadata, app.ResourceContract{})
	if err != nil {
		return err
	}
	s.catalogs = map[string]*scopeCatalog{
		"visibility": {execution: execution, owner: s.scopeRepo},
		"tenants":    {execution: execution, owner: s.tenantRepo},
		"roles":      {execution: execution, owner: s.roleRepo},
		"users":      {execution: execution, owner: s.userRepo},
		"bindings":   {execution: execution, owner: s.userRepo},
		"groups":     {execution: execution, owner: s.groupRepo},
	}
	fact, err := auth.NewFact("iam.scope.platform_coverage", func(ctx context.Context, _ auth.Request) (platformScopeFact, error) {
		principal, err := hostauthz.RequirePrincipal(ctx)
		if err != nil {
			return platformScopeFact{}, err
		}
		if principal.ActiveScopeID <= 0 {
			return platformScopeFact{}, errors.NewCode(errors.Unauthorized, "active scope is required")
		}
		// Provisioning remains in EnsurePlatformScope; authorization facts only read.
		root, err := s.scopeRepo.FindByKey(ctx, "platform")
		if err != nil {
			return platformScopeFact{}, err
		}
		active := root
		if principal.ActiveScopeID != root.ID {
			active, err = s.scopeRepo.Get(ctx, principal.ActiveScopeID)
			if err != nil {
				return platformScopeFact{}, err
			}
		}
		covers, err := s.scopeRepo.ScopeCovers(ctx, active.ID, root.ID)
		return platformScopeFact{ActiveID: active.ID, RootID: root.ID, CoversRoot: covers}, err
	})
	if err != nil {
		return err
	}
	s.commands = map[string]*scopeCommand{}
	actions := []string{"create", "update", "activate", "deactivate", "delete", "repair", "governance", "list", "visibility"}
	for _, action := range []string{"create", "update", "activate", "deactivate", "delete", "repair", "list", "visibility"} {
		actions = append(actions, "http_"+action)
	}
	for _, action := range actions {
		base := strings.TrimPrefix(action, "http_")
		read := base == "governance" || base == "list" || base == "visibility"
		policy := scopeAccessPolicy{read: read, http: strings.HasPrefix(action, "http_")}
		if !read {
			policy.fact = fact
		}
		kind := auth.KindUpdate
		if read {
			kind = auth.KindRead
		} else if base == "create" {
			kind = auth.KindCreate
		} else if base == "delete" {
			kind = auth.KindDelete
		}
		resources := []app.CommandResource[scopeCommandInput]{}
		names := []string{"tree"}
		if base != "visibility" && base != "create" {
			names = append(names, "tenants")
		}
		if base == "governance" || base == "list" || base == "delete" || action == "http_repair" {
			names = append(names, "roles", "users", "bindings", "groups")
		}
		if base == "visibility" || base == "create" || base == "delete" {
			names = append(names, "visibility")
		}
		for _, name := range names {
			provider := app.IExecutionDescriptorProvider(s.scopeRepo)
			resourceKind := kind
			path := "CommandReader/Writer -> full authorized platform scope tree -> native lookup/count and versioned writes"
			if name != "tree" {
				provider = s.catalogs[name]
				resourceKind = auth.KindRead
				path = "CommandReader -> full authorized " + name + " governance projection -> existing scope ID and tenant predicates"
				if name == "visibility" && !read {
					resourceKind = auth.KindUpdate
					path = "CommandWriter -> full scope visibility catalog -> rebuild from current tree in the scope transaction"
				}
			}
			authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: "iam.scope." + name, Actions: []auth.Action{{Name: action, Kind: resourceKind, Permission: svc.AdminEntryPermission.Code}}}, ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{ID: "iam.scope.governance", System: auth.SystemCheckConstraints, Constraints: []auth.IPolicy{policy}}}}, auth.CompileOptions{Metadata: provider.ExecutionDescriptor().Metadata(), Checker: hostauthz.NewActionChecker()})
			if err != nil {
				return err
			}
			resource := app.CommandResource[scopeCommandInput]{Name: name, Repository: provider, Authorizer: authorizer, Action: action, ConditionPath: path, Intent: func(in scopeCommandInput) (auth.Request, error) {
				if in.Action != action {
					return auth.Request{}, errors.NewCode(errors.InvalidInput, "scope action differs from its frozen intent")
				}
				return auth.Request{}, nil
			}}
			if name != "tree" && !read {
				resource.ReuseFactsFrom = "tree"
			}
			resources = append(resources, resource)
		}
		command, err := app.NewCommand(app.CommandOptions[scopeCommandInput, *scopeAccess, ScopeCommandResult]{Resources: resources, Access: func(_ context.Context, in scopeCommandInput, grants []*app.CommandGrant) (*scopeAccess, error) {
			return s.bindAccess(in, names, grants)
		}, Handler: func(ctx context.Context, in scopeCommandInput, access *scopeAccess) (ScopeCommandResult, error) {
			if err := access.check(ctx); err != nil {
				return ScopeCommandResult{}, err
			}
			if read {
				return s.handleScopeCommand(ctx, in, access)
			}
			var result ScopeCommandResult
			err := s.scopeRepo.WithinTx(ctx, func(txCtx context.Context) error {
				var err error
				result, err = s.handleScopeCommand(txCtx, in, access)
				return err
			})
			return result, err
		}})
		if err != nil {
			return err
		}
		s.commands[action] = command
	}
	return nil
}

func (s *ScopeService) handleScopeCommand(ctx context.Context, in scopeCommandInput, access *scopeAccess) (ScopeCommandResult, error) {
	var out ScopeCommandResult
	var err error
	switch strings.TrimPrefix(in.Action, "http_") {
	case "create":
		out.Scope, err = s.createScope(ctx, in.Create, access)
	case "update":
		out.Scope, err = s.updateScope(ctx, in.ID, in.Update, access)
	case "activate", "deactivate":
		status := iamentity.ScopeStatusActive
		if strings.HasSuffix(in.Action, "deactivate") {
			status = iamentity.ScopeStatusInactive
		}
		out.Scope, err = s.updateScope(ctx, in.ID, &svc.UpdateScopeRequest{Status: status}, access)
	case "delete":
		err = s.deleteScope(ctx, in.ID, access)
	case "repair":
		out.Scope, err = s.repairScope(ctx, in.ID, access)
		if err == nil && in.Action == "http_repair" {
			out.Governance, err = s.evaluateScopeGovernanceState(ctx, out.Scope, access)
		}
	case "governance":
		out.Governance, err = s.governanceState(ctx, in.ID, access)
	case "list":
		var items []*iamentity.Scope
		items, err = access.list(ctx)
		if err == nil {
			out.Items = make([]ScopeView, 0, len(items))
			for _, item := range items {
				if item == nil {
					continue
				}
				state, stateErr := s.evaluateScopeGovernanceState(ctx, item, access)
				if stateErr != nil {
					return ScopeCommandResult{}, stateErr
				}
				out.Items = append(out.Items, ScopeView{Scope: item, Governance: state})
			}
		}
	case "visibility":
		out.VisibleIDs, err = access.visibilityRead.Read(ctx, in.ID)
		if err == nil {
			out.VisibleItems = make([]*iamentity.Scope, 0, len(out.VisibleIDs))
			for _, id := range out.VisibleIDs {
				item, readErr := access.get(ctx, id)
				if errors.Is(readErr, errors.NotFound) {
					continue
				}
				if readErr != nil {
					return ScopeCommandResult{}, readErr
				}
				out.VisibleItems = append(out.VisibleItems, item)
			}
		}
	}
	return out, err
}

func (s *ScopeService) execute(ctx context.Context, action string, input ScopeCommandInput) (ScopeCommandResult, error) {
	command := s.commands[action]
	if command == nil {
		return ScopeCommandResult{}, errors.NewCode(errors.InvalidInput, "scope action is not declared")
	}
	return command.Execute(ctx, scopeCommandInput{ScopeCommandInput: input, Action: action})
}
func (s *ScopeService) ExecuteHTTP(ctx context.Context, action string, input ScopeCommandInput) (ScopeCommandResult, error) {
	return s.execute(ctx, "http_"+action, input)
}
func (s *ScopeService) AuthorizationBinding(action string) (auth.EntryBinding, error) {
	command := s.commands["http_"+action]
	if command == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "scope HTTP action is not declared")
	}
	return command.AuthorizationBinding()
}
func (s *ScopeService) CreateScope(ctx context.Context, req *svc.CreateScopeRequest) (*iamentity.Scope, error) {
	out, err := s.execute(ctx, "create", ScopeCommandInput{Create: req})
	return out.Scope, err
}
func (s *ScopeService) UpdateScope(ctx context.Context, id int64, req *svc.UpdateScopeRequest) (*iamentity.Scope, error) {
	out, err := s.execute(ctx, "update", ScopeCommandInput{ID: id, Update: req})
	return out.Scope, err
}
func (s *ScopeService) ActivateScope(ctx context.Context, id int64) error {
	_, err := s.execute(ctx, "activate", ScopeCommandInput{ID: id})
	return err
}
func (s *ScopeService) DeactivateScope(ctx context.Context, id int64) error {
	_, err := s.execute(ctx, "deactivate", ScopeCommandInput{ID: id})
	return err
}
func (s *ScopeService) DeleteScope(ctx context.Context, id int64) error {
	_, err := s.execute(ctx, "delete", ScopeCommandInput{ID: id})
	return err
}
func (s *ScopeService) RepairScope(ctx context.Context, id int64) (*iamentity.Scope, error) {
	out, err := s.execute(ctx, "repair", ScopeCommandInput{ID: id})
	return out.Scope, err
}
func (s *ScopeService) ScopeGovernanceState(ctx context.Context, id int64) (*svc.ScopeGovernanceState, error) {
	out, err := s.execute(ctx, "governance", ScopeCommandInput{ID: id})
	return out.Governance, err
}
