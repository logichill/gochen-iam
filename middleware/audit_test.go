package middleware

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"gochen/logging"
)

func TestAuditMiddlewareKeepsLoggerRequestScoped(t *testing.T) {
	var firstOutput bytes.Buffer
	var secondOutput bytes.Buffer
	firstLogger := logging.NewLogger(logging.Config{Writer: &firstOutput, Level: logging.WarnLevel})
	secondLogger := logging.NewLogger(logging.Config{Writer: &secondOutput, Level: logging.WarnLevel})
	firstContext := newTestHTTPContext(t, "GET", "/first")
	secondContext := newTestHTTPContext(t, "GET", "/second")

	if err := AuditMiddleware(firstLogger, nil)(firstContext, func() error {
		recordAuthzDenied(firstContext, AuditRecord{Decision: "deny", Reason: "first denial"})
		return nil
	}); err != nil {
		t.Fatalf("first AuditMiddleware() error = %v", err)
	}
	if err := AuditMiddleware(secondLogger, nil)(secondContext, func() error {
		recordAuthzDenied(secondContext, AuditRecord{Decision: "deny", Reason: "second denial"})
		return nil
	}); err != nil {
		t.Fatalf("second AuditMiddleware() error = %v", err)
	}

	if got := firstOutput.String(); !strings.Contains(got, "first denial") || strings.Contains(got, "second denial") {
		t.Fatalf("first logger output = %q", got)
	}
	if got := secondOutput.String(); !strings.Contains(got, "second denial") || strings.Contains(got, "first denial") {
		t.Fatalf("second logger output = %q", got)
	}
}

func TestRecordAuthzDeniedWithoutAuditMiddlewareIsNoop(t *testing.T) {
	ctx := newTestHTTPContext(t, "GET", "/without-audit")
	recordAuthzDenied(ctx, AuditRecord{Decision: "deny", Reason: "not configured"})
}

func TestAuditMiddlewarePreservesUpstreamRecorder(t *testing.T) {
	var upstreamOutput bytes.Buffer
	var nestedOutput bytes.Buffer
	upstreamLogger := logging.NewLogger(logging.Config{Writer: &upstreamOutput, Level: logging.WarnLevel})
	nestedLogger := logging.NewLogger(logging.Config{Writer: &nestedOutput, Level: logging.WarnLevel})
	sink := &recordingAuditSink{}
	ctx := newTestHTTPContext(t, "GET", "/nested")

	err := AuditMiddleware(upstreamLogger, sink)(ctx, func() error {
		return AuditMiddleware(nestedLogger, nil)(ctx, func() error {
			recordAuthzDenied(ctx, AuditRecord{Decision: "deny", Reason: "preserve upstream"})
			return nil
		})
	})
	if err != nil {
		t.Fatalf("nested AuditMiddleware() error = %v", err)
	}
	if len(sink.records) != 1 || sink.records[0].Reason != "preserve upstream" {
		t.Fatalf("sink records = %#v, want upstream deny record", sink.records)
	}
	if got := upstreamOutput.String(); !strings.Contains(got, "preserve upstream") {
		t.Fatalf("upstream logger output = %q, want deny record", got)
	}
	if got := nestedOutput.String(); got != "" {
		t.Fatalf("nested logger should not replace upstream recorder, got %q", got)
	}
}

type recordingAuditSink struct {
	records []AuditRecord
}

func (s *recordingAuditSink) Record(_ context.Context, record AuditRecord) {
	s.records = append(s.records, record)
}
