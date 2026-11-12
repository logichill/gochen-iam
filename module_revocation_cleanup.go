package iam

import (
	"context"
	"sync"
	"time"

	hostauthz "gochen-runtime/host/authz"
	"gochen-runtime/host/capability"
	"gochen/app"
	"gochen/auth"
	"gochen/contextx"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
	"gochen/observe/logging"
	"gochen/process/task"
)

const revocationCleanupTask = "iam.revocation:cleanup_expired"
const revocationLedgerID = "access_tokens"

type revokedTokenCleaner interface {
	CleanupExpired(context.Context) (int64, error)
}

// revocationLedger 表达现有全局吊销存储的整体身份，物理表及过期清理规则保持原有契约。
type revocationLedger struct {
	ID string `entity:"id"`
}

type revocationCleanupResource struct {
	cleaner   revokedTokenCleaner
	execution app.ExecutionDescriptor
}

func (r *revocationCleanupResource) ExecutionDescriptor() app.ExecutionDescriptor { return r.execution }

type revocationCleanupPolicy struct{}

func (revocationCleanupPolicy) Vocabulary() auth.Vocabulary {
	return auth.Vocabulary{Refs: []meta.Ref{meta.ID()}}
}
func (revocationCleanupPolicy) Evaluate(ctx context.Context, _ auth.Request) (auth.Decision, error) {
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok || !principal.System || contextx.TenantID(ctx) != "" {
		return auth.Decision{Reason: "revocation_cleanup_requires_global_system"}, nil
	}
	return auth.Decision{Allowed: true, Spec: spec.Eq(meta.ID(), revocationLedgerID)}, nil
}

type revocationCleanupCommand = app.Command[revocationLedger, *app.CommandIdentityCall[revocationLedger, string, int64], int64]

type revocationCleanup struct {
	mu      sync.Mutex
	tasks   *task.Registry
	command *revocationCleanupCommand
	logger  logging.ILogger
	cancel  context.CancelFunc
	running bool
}

func newRevocationCleanup(cleaner revokedTokenCleaner, logger logging.ILogger) (*revocationCleanup, error) {
	metadata, err := meta.Describe[*revocationLedger]()
	if err != nil {
		return nil, err
	}
	execution, err := app.BindContract(metadata, app.ResourceContract{})
	if err != nil {
		return nil, err
	}
	resource := &revocationCleanupResource{cleaner: cleaner, execution: execution}
	authorizer, err := auth.Compile(auth.Declaration{
		Descriptor:     auth.Descriptor{Resource: "iam.revocation_ledger", Actions: []auth.Action{{Name: "cleanup_expired", Kind: auth.KindDelete, Permission: "api:token:cleanup"}}},
		ResourceAccess: auth.ResourceAccessData,
		Rules:          []auth.Rule{{ID: "iam.revocation.global_system_cleanup", System: auth.SystemCheckConstraints, Constraints: []auth.IPolicy{revocationCleanupPolicy{}}}},
	}, auth.CompileOptions{Metadata: metadata, Checker: hostauthz.NewActionChecker()})
	if err != nil {
		return nil, err
	}
	command, err := app.NewCommand(app.CommandOptions[revocationLedger, *app.CommandIdentityCall[revocationLedger, string, int64], int64]{
		Resources: []app.CommandResource[revocationLedger]{{Name: "revocation_ledger", Repository: resource, Authorizer: authorizer, Action: "cleanup_expired", ConditionPath: "CommandIdentityCall(global access-token ledger) -> RevokedTokenStore.CleanupExpired(expiry + clock skew, bounded batches)", Intent: func(input revocationLedger) (auth.Request, error) { return auth.Request{IDs: []string{input.ID}}, nil }}},
		Access: func(_ context.Context, _ revocationLedger, grants []*app.CommandGrant) (*app.CommandIdentityCall[revocationLedger, string, int64], error) {
			return app.NewCommandIdentityCall(resource, grants[0], func(input revocationLedger) string { return input.ID }, func(ctx context.Context, _ revocationLedger) (int64, error) {
				return resource.cleaner.CleanupExpired(ctx)
			})
		},
		Handler: func(ctx context.Context, input revocationLedger, access *app.CommandIdentityCall[revocationLedger, string, int64]) (int64, error) {
			return access.Call(ctx, input)
		},
	})
	if err != nil {
		return nil, err
	}
	r := &revocationCleanup{command: command, logger: logging.ComponentLogger("iam.revocation.cleanup", logger)}
	r.tasks, err = task.NewRegistry(task.NewTaskSupervisorWithLogger("iam.revocation.cleanup", r.logger))
	if err != nil {
		return nil, err
	}
	if err := r.tasks.Register(revocationCleanupTask, r.run); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *revocationCleanup) AuthorizationEntries(context.Context) ([]hostauthz.EntryRegistration, error) {
	binding, err := r.command.AuthorizationBinding()
	if err != nil {
		return nil, err
	}
	binding.Entry = auth.Entry{Kind: "worker", Key: revocationCleanupTask}
	source, err := hostauthz.NewHandlerEntries("worker", r.tasks)
	if err != nil {
		return nil, err
	}
	return []hostauthz.EntryRegistration{{Source: source, Bindings: []auth.EntryBinding{binding}}}, nil
}

func (r *revocationCleanup) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.NewCode(errors.InvalidInput, "revocation cleanup context is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		return errors.NewCode(errors.Conflict, "revocation cleanup is already running")
	}
	registrations, err := r.AuthorizationEntries(ctx)
	if err != nil {
		return err
	}
	registry := hostauthz.NewEntryRegistry(registrations[0].Source)
	if err := registry.Bind(registrations[0].Bindings[0]); err != nil {
		return err
	}
	if err := registry.ValidateEntries(ctx, nil); err != nil {
		return err
	}
	if err := registry.ActivateEntries(); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	runCtx, err = hostauthz.WithPrincipal(runCtx, hostauthz.Principal{SubjectID: "system:iam-revocation-cleanup", IsSystem: true})
	if err != nil {
		cancel()
		return err
	}
	runCtx, err = hostauthz.WithExecutionMetadata(runCtx, hostauthz.ExecutionMetadata{Source: "iam.revocation.cleanup", JobID: revocationCleanupTask})
	if err != nil {
		cancel()
		return err
	}
	if err := r.tasks.Go(runCtx, revocationCleanupTask); err != nil {
		cancel()
		return err
	}
	r.cancel, r.running = cancel, true
	return nil
}

func (r *revocationCleanup) run(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			cleanupCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			deleted, err := r.command.Execute(cleanupCtx, revocationLedger{ID: revocationLedgerID})
			if err != nil {
				r.logger.Warn(cleanupCtx, "iam revoked token cleanup failed", logging.Error(err), logging.Int64("deleted", deleted))
			}
			cancel()
		}
	}
}

func (r *revocationCleanup) Stop(ctx context.Context) error {
	if ctx == nil {
		return errors.NewCode(errors.InvalidInput, "revocation cleanup stop context is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running {
		return nil
	}
	r.cancel()
	if err := r.tasks.Stop(ctx); err != nil {
		return err
	}
	r.running = false
	return nil
}

// AuthorizationEntries 暴露 IAM 自身维护任务的实际注册源。
func (m *iamModule) AuthorizationEntries(ctx context.Context) ([]hostauthz.EntryRegistration, error) {
	return m.cleanup.AuthorizationEntries(ctx)
}

// RuntimeComponents 转交底层模块的真实组件，供 Host 完整核对。
func (m *iamModule) RuntimeComponents() ([]capability.IRuntimeComponent, error) {
	if provider, ok := m.IModule.(capability.IRuntimeComponentProvider); ok {
		return provider.RuntimeComponents()
	}
	return nil, nil
}
