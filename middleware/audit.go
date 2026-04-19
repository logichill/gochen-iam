package middleware

import (
	"context"
	"gochen/contextx"
	"gochen/httpx"
	"gochen/logging"
	"os"
)

// AuditRecord 表示一次鉴权/授权决策的审计记录（默认仅记录 deny）。
type AuditRecord struct {
	Decision   string // "deny" | "allow"（当前默认只写 deny）
	Reason     string // 业务可读原因
	Path       string
	Method     string
	UserID     int64
	TenantID   string
	Role       string // RoleMiddleware(requiredRole)
	Permission string // PermissionMiddleware(requiredPermission)
}

// IAuditSink 可选的审计落点（默认 nil）。
// 可在上层应用装配期注入（例如写日志、写队列、写审计系统）。
type IAuditSink interface {
	Record(ctx context.Context, rec AuditRecord)
}

var (
	auditSink   IAuditSink
	auditLogger = logging.ComponentLogger("iam.middleware.audit")
)

// isAuditLogEnabled 判断审计日志Enabled。
func isAuditLogEnabled() bool {
	v := os.Getenv("AUTH_AUDIT_LOG")
	return v == "" || v == "true" || v == "1"
}

// SetAuditSink 设置审计Sink。
func SetAuditSink(sink IAuditSink) {
	auditSink = sink
}

// SetAuditLogger 允许上层注入 logger（例如与应用级 logger 对齐）。
func SetAuditLogger(logger logging.ILogger) {
	if logger != nil {
		auditLogger = logger
	}
}

// recordAuthzDenied 处理记录AuthzDenied。
func recordAuthzDenied(ctx httpx.IContext, rec AuditRecord) {
	if ctx == nil {
		return
	}
	req := ctx.Request()
	stdCtx := contextx.Background()
	if req != nil {
		rec.Method = req.Method
		stdCtx = req.Context()
	}
	rec.Path = ctx.Path()

	reqCtx := ctx.RequestContext()
	if reqCtx != nil {
		rec.UserID = GetUserID(reqCtx)
		rec.TenantID = GetTenantID(reqCtx)
	}

	if auditSink != nil {
		auditSink.Record(stdCtx, rec)
	}

	if auditLogger != nil && isAuditLogEnabled() {
		auditLogger.Warn(stdCtx, "[authz] denied",
			logging.String("reason", rec.Reason),
			logging.String("path", rec.Path),
			logging.String("method", rec.Method),
			logging.Int64("user_id", rec.UserID),
			logging.String("tenant_id", rec.TenantID),
			logging.String("role", rec.Role),
			logging.String("permission", rec.Permission),
		)
	}
}
