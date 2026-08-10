package middleware

import (
	"context"
	"os"

	"gochen/contextx"
	"gochen/httpx"
	"gochen/logging"
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

const auditRecorderContextKey = "gochen-iam.audit.recorder"

type auditRecorder struct {
	sink   IAuditSink
	logger logging.ILogger
}

// isAuditLogEnabled 判断审计日志Enabled。
func isAuditLogEnabled() bool {
	v := os.Getenv("AUTH_AUDIT_LOG")
	return v == "" || v == "true" || v == "1"
}

// AuditMiddleware 为当前请求注入实例级授权审计依赖。
// 调用方应在 AuthMiddleware、PermissionMiddleware 等鉴权中间件之前挂载。
// 若上游组合根已注入 recorder，则保留上游配置，避免模块级默认值覆盖外部 sink。
func AuditMiddleware(logger logging.ILogger, sink IAuditSink) httpx.Middleware {
	recorder := &auditRecorder{sink: sink, logger: logger}
	return func(ctx httpx.IContext, next func() error) error {
		if ctx != nil && auditRecorderFromContext(ctx) == nil {
			ctx.Set(auditRecorderContextKey, httpx.ValueOf(recorder))
		}
		return next()
	}
}

func auditRecorderFromContext(ctx httpx.IContext) *auditRecorder {
	if ctx == nil {
		return nil
	}
	value, ok := ctx.Get(auditRecorderContextKey)
	if !ok {
		return nil
	}
	recorder, ok := httpx.ValueAs[*auditRecorder](value)
	if !ok {
		return nil
	}
	return recorder
}

// recordAuthzDenied 处理记录AuthzDenied。
func recordAuthzDenied(ctx httpx.IContext, rec AuditRecord) {
	recorder := auditRecorderFromContext(ctx)
	if recorder == nil {
		return
	}
	stdCtx := contextx.Background()
	if reqCtx := ctx.RequestContext(); reqCtx != nil {
		stdCtx = reqCtx
	}
	rec.Method = ctx.Method()
	rec.Path = ctx.Path()

	reqCtx := ctx.RequestContext()
	if reqCtx != nil {
		rec.UserID = GetUserID(reqCtx)
		rec.TenantID = GetTenantID(reqCtx)
	}

	if recorder.sink != nil {
		recorder.sink.Record(stdCtx, rec)
	}

	if recorder.logger != nil && isAuditLogEnabled() {
		recorder.logger.Warn(stdCtx, "[authz] denied",
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
