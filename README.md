# gochen-iam

`gochen-iam` 是基于 `gochen` 的可复用 IAM（Identity & Access Management）领域模块，当前已经切换到分层授权最终设计：

- 认证采用两阶段登录：`Authenticate -> ActivateScope`
- 授权运行时统一围绕 `Principal.ActiveScopeID`
- 资源归属统一围绕 `managed_scope_id` / `namespace_scope_id`
- 查询边界统一围绕 `DataScope.VisibleScopeIDs`
- 最终写边界统一围绕 `AuthzDecision -> WriteConstraint`
- `platform tenant`、`tenants.is_platform`、`platform_slot`、`scope_type/scope_code` 查询过滤都已移除

> 菜单仅用于“导航可见性”，不作为安全边界。真正的安全边界必须由服务端 API 权限校验保证。

## 当前模型

### 授权树

系统维护一棵正式的 scope 树：

- `scopes`
- `scope_visibility_map`

约束：

- `platform` 是唯一根 scope
- 每个 tenant 只通过 `tenants.root_scope_id` 连接到授权树
- `scope_visibility_map` 是 scope 树的预展开投影，供高频查询直接消费

### 业务对象

核心业务表当前语义如下：

- `tenants`：业务租户，仅包含 `root_scope_id`
- `users`：`tenant_id + home_tenant_id + home_scope_id + managed_scope_id + owner_id`
- `groups`：`tenant_id + managed_scope_id + owner_id`
- `roles`：`tenant_id + namespace_scope_id + owner_id + permissions`
- `user_role_bindings`：`user_id + role_id + grant_scope_id`

约束：

- `tenant_id` 仍保留为业务字段，用于租户内唯一性与请求归一化
- 真正的授权边界统一由 `managed_scope_id` / `namespace_scope_id` 与 `scope_visibility_map` 表达
- `scope_type / scope_code` 不再作为资源主表达字段，也不再参与 repo 高频过滤
- `platform` 是 scope，不是 tenant

## 快速接入

`gochen-iam` 以 gochen 模块方式提供能力：

- 模块入口：`module.go`
- 路由注册：`router/*.go`
- 中间件：`middleware/*.go`
- 领域服务：`service/*`

上层应用通常只需要：

1. 注册 `gochen-iam` 模块
2. 在 HTTP 层挂载 `AuthMiddleware(...)` 或 `OptionalAuthMiddleware(...)`
3. 在业务接口使用 `PermissionMiddleware(...)`、`AdminOnlyMiddleware()`、`PlatformScopeMiddleware()` 等入口 guard
4. 通过标准 repo / service / CRUD builder 使用自动注入的数据边界与写边界

## 认证（JWT）

### 两阶段登录

登录不再推断 active scope，而是显式两阶段：

1. `POST /auth/login`
   - 输入：用户名、密码
   - 输出：`activation_token`、`binding_version`、`available_scopes`
2. `POST /auth/activate-scope`
   - 输入：`activation_token` + `scope_id`
   - 输出：正式 access token

`available_scopes` 会返回：

- `scope_id`
- `scope_key`
- `scope_kind`
- `binding_ids`
- `role_names`
- `permissions`

### Access Token 语义

最终 access token 只保存最小授权语义：

- `user_id`
- `active_scope_id`
- `binding_version`
- `permissions`（缓存 hint，可为空）

运行时不会再把 `tenant 是否 platform`、`active_scope_code`、`active_scope_type` 之类派生语义塞回 token。

### 中间件注入

`AuthMiddleware` / `OptionalAuthMiddleware` 验证 access token 后，会注入：

- `user_id`
- `tenant_id`（业务请求租户）
- `Principal`
- `ActiveScopeID`
- `ActiveScopeKind`
- `DataScope.VisibleScopeIDs`
- `permissions`

其中 `VisibleScopeIDs` 通过 `AuthContextResolver` 从 `active_scope_id` 回源解析，而不是依赖 token 内部冗余字段。

### 关键环境变量

`middleware.DefaultAuthConfig()` 当前会读取：

- `AUTH_SECRET`
- `AUTH_ACCESS_TOKEN_TTL`
- `AUTH_ALLOW_QUERY_TOKEN`
- `AUTH_REQUIRE_TENANT`
- `AUTH_ALLOW_TENANT_QUERY`
- `AUTH_TENANT_HEADER`
- `IAM_TENANT_MODE`
- `IAM_SINGLE_TENANT_ID`

补充：

- `AUTH_ALLOW_QUERY_TOKEN` 仅允许 dev/test 环境开启
- `AUTH_REQUIRE_TENANT` 控制业务请求是否必须显式提供请求租户
- 单租户模式只影响业务 tenant 归一化，不影响 active scope 选择模型

## 授权（RBAC + Scope）

### 中间件与辅助函数

- `middleware.RoleMiddleware(role)`
- `middleware.PermissionMiddleware(permission)`
- `middleware.AdminOnlyMiddleware()`
- `middleware.PlatformScopeMiddleware()`
- `middleware.UserOnlyMiddleware()`

说明：

- `AdminOnlyMiddleware()` 要求当前 active scope 内具备 `*:*:*`
- `PlatformScopeMiddleware()` 要求当前 active scope kind 为 `platform`
- `PermissionMiddleware(...)` 既做运行期校验，也会把权限注册进 required permissions registry

### 权限码格式

权限码统一为三段式：

- `type:resource:action`
- 例如：`api:user:read`、`api:menu:publish`、`menu:dashboard.home:view`

仅支持整段通配：

- `api:*:*`
- `menu:*:view`
- `*:*:*`

## 查询与写入边界

### 查询

repo / orm 默认围绕资源归属字段注入边界：

- `users.managed_scope_id`
- `groups.managed_scope_id`
- `roles.namespace_scope_id`

运行时流程：

1. 从 access token 恢复 `ActiveScopeID`
2. 由 `AuthContextResolver` / `ScopeAuthorizer` 解出 `VisibleScopeIDs`
3. repo 把边界翻译成 `managed_scope_id in (...)` 或等价 join `scope_visibility_map`

### 写入

所有正式写操作最终都围绕显式 `WriteConstraint` 落库：

- service 先做 `Authorize(...)`
- 将 allow 决策投影成 `WriteConstraint`
- repo 在最终 `INSERT / UPDATE / DELETE` 处校验：
  - 资源 ID
  - `managed_scope_id`
  - `revision/version`

这意味着：

- 不能只在 router/service 做前置 tenant 判断后直接写库
- 不能依赖隐式 context 猜测最终写边界
- `RowsAffected = 0` 不会被当成“静默成功”

## 多租户（tenant）

默认约定 tenant 通过 `X-Tenant-ID`（或 `AUTH_TENANT_HEADER`）传入。

当前模型里：

- tenant 是业务对象
- scope 是授权对象
- 请求 tenant 决定“当前操作哪个业务租户”
- active scope 决定“当前以哪个授权域工作”

因此：

- 平台管理员使用 platform scope 的 token 时，仍可显式指定目标业务 tenant
- 不再存在 `platform tenant`
- 也不再通过 tenant 魔法值推断 active scope

## 菜单模块（menu）

菜单模块用于后台系统的导航结构与可见性配置。

### 数据模型

- `entity.MenuItem` -> `menu_items`
- 关键字段：`code`、`parent_id`、`title`、`path`、`component`、`published`
- 菜单定义本身视为平台级配置资源

### 可见性规则

`GET /menus/me` 当前逻辑：

1. 只返回 `published=true`
2. `hidden=true` 或 `disabled=true` 直接过滤
3. `all_of_permissions` 必须全部满足
4. `any_of_permissions` 至少满足一个
5. 父节点无权限但子节点可见时，保留父节点以承载子树

### 管理接口

当前菜单后台路由要求：

- `AdminOnlyMiddleware()`
- 对应 `PermissionMiddleware("api:menu:read|write|publish")`

## 数据库迁移 / 回填

本仓库本身不内置统一生产迁移器；生产环境建议使用显式 migration。

若从旧模型升级到当前最终模型，最少需要完成以下步骤：

1. 建立正式 scope 树
   - 创建 `scopes`
   - 创建 `scope_visibility_map`
   - 初始化唯一 platform scope
2. 改造 tenant
   - 为 `tenants` 增加 `root_scope_id`
   - 为每个 tenant 创建 tenant root scope
   - 回填 `tenants.root_scope_id`
   - 删除 `is_platform` / `platform_slot`
3. 改造用户
   - 补齐 `home_tenant_id`
   - 补齐 `home_scope_id`
   - 补齐 `managed_scope_id`
   - 补齐 `owner_id`
4. 改造角色
   - 补齐 `namespace_scope_id`
   - 补齐 `owner_id`
   - 统一 role namespace 到正式 scope
5. 改造组织与其他受控资源
   - 补齐 `managed_scope_id`
   - 补齐 `owner_id`
6. 建立正式绑定
   - 创建 `user_role_bindings`
   - 从旧 `user_roles` 回填 `grant_scope_id`
7. 清理旧实现
   - 删除 `platform tenant` 相关逻辑
   - 删除 repo 里基于 `scope_type / scope_code` 的等值过滤
   - 删除基于 tenant 推断 active scope 的登录逻辑

生产迁移建议额外保证：

- `scope_visibility_map(viewer_scope_id, target_scope_id)` 有主键/索引
- 每张受控资源表对 `managed_scope_id` 建索引
- `user_role_bindings(user_id, role_id, grant_scope_id)` 建唯一约束
- 迁移完成后用真实业务账号验证 `Authenticate -> ActivateScope` 流程

## 开发与验证

常用验证命令：

```bash
cd /home/alex/data/priv/project/gochen-iam && go test ./... -count=1
cd /home/alex/data/priv/project/gochen && go test ./... -count=1
cd /home/alex/data/priv/project/alife && go test ./internal/progress/... ./internal/shop/... ./cmd/migrate -count=1
```

工程约定：

- 默认忽略 `.cache/.gocache`
- Go 代码修改后执行 `gofmt`
- 不保留兼容层，不维持双语义路径
