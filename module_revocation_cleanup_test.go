package iam

import (
	"context"
	"testing"
	"time"

	iammw "gochen-iam/middleware"
	"gochen-runtime/db/sql/stdsql"
	hostauthz "gochen-runtime/host/authz"
	"gochen/auth"
	"gochen/contextx"
	"gochen/db"
	"gochen/errors"
	"gochen/observe/logging"
)

type recordingTokenCleaner struct{ calls int }

func (c *recordingTokenCleaner) CleanupExpired(context.Context) (int64, error) {
	c.calls++
	return 1, nil
}

func TestRevocationCleanupAuthorizesGlobalLedgerBeforeAccess(t *testing.T) {
	cleaner := &recordingTokenCleaner{}
	worker, err := newRevocationCleanup(cleaner, logging.NewNoopLogger())
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := hostauthz.WithPrincipal(t.Context(), hostauthz.Principal{SubjectID: "admin", Permissions: []string{"api:token:cleanup"}})
	if err != nil {
		t.Fatal(err)
	}
	system, err := hostauthz.WithPrincipal(t.Context(), hostauthz.Principal{SubjectID: "system:cleanup", IsSystem: true})
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := contextx.WithTenantID(system, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	tenant, err = hostauthz.WithPrincipal(tenant, hostauthz.Principal{SubjectID: "system:cleanup", IsSystem: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{t.Context(), ordinary, tenant} {
		if _, err := worker.command.Execute(ctx, revocationLedger{ID: revocationLedgerID}); err == nil || cleaner.calls != 0 {
			t.Fatalf("unauthorized cleanup=%v calls=%d", err, cleaner.calls)
		}
	}
	if _, err := worker.command.Execute(system, revocationLedger{ID: "other-ledger"}); !errors.Is(err, errors.Forbidden) || cleaner.calls != 0 {
		t.Fatalf("wrong ledger cleanup=%v calls=%d", err, cleaner.calls)
	}
	if count, err := worker.command.Execute(system, revocationLedger{ID: revocationLedgerID}); err != nil || count != 1 || cleaner.calls != 1 {
		t.Fatalf("global cleanup count=%d err=%v calls=%d", count, err, cleaner.calls)
	}
	registrations, err := worker.AuthorizationEntries(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	registry := hostauthz.NewEntryRegistry(registrations[0].Source)
	if err := registry.ValidateEntries(t.Context(), nil); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("missing cleanup binding=%v", err)
	}
	if err := worker.tasks.Go(t.Context(), revocationCleanupTask); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("unvalidated worker ran: %v", err)
	}
	if err := registry.Bind(registrations[0].Bindings[0]); err != nil {
		t.Fatal(err)
	}
	if err := registry.ValidateEntries(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	report := registry.Report()
	if len(report) != 1 || report[0].Class != auth.EntryDeclared || report[0].ResourceAccess != auth.ResourceAccessData {
		t.Fatalf("cleanup resource classification=%+v", report)
	}
}

func TestRevocationCleanupCommandPreservesExpiryGraceInDatabase(t *testing.T) {
	database, err := stdsql.New(db.DBConfig{Driver: "sqlite3", Database: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := iammw.EnsureDatabaseRevokedTokenSchema(t.Context(), database); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := database.Exec(t.Context(), "INSERT INTO iam_revoked_tokens(jti, expires_at) VALUES (?, ?), (?, ?), (?, ?)", "expired", now.Add(-time.Hour).Unix(), "within-grace", now.Add(-time.Minute).Unix(), "valid", now.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	store, err := iammw.NewDatabaseRevokedTokenStore(database)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := newRevocationCleanup(store, logging.NewNoopLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := hostauthz.WithPrincipal(t.Context(), hostauthz.Principal{SubjectID: "system:cleanup", IsSystem: true})
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := worker.command.Execute(ctx, revocationLedger{ID: revocationLedgerID})
	if err != nil || deleted != 1 {
		t.Fatalf("deleted=%d err=%v", deleted, err)
	}
	for _, id := range []string{"within-grace", "valid"} {
		revoked, err := store.IsRevoked(t.Context(), id)
		if err != nil || !revoked {
			t.Fatalf("retained token %s revoked=%v err=%v", id, revoked, err)
		}
	}
}
