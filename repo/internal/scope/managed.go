package scope

import (
	iamauth "gochen-iam/auth"
)

// DefaultResolver 为 IAM 仓储提供默认数据范围解析，直接复用统一事实源。
var DefaultResolver = iamauth.DefaultDataScopeResolver

// ResolveManagedScopeID 解析用于受管范围写入的 scope ID，直接复用统一事实源。
var ResolveManagedScopeID = iamauth.ResolveManagedScopeID
