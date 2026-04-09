# gochen-iam

`gochen-iam` 是基于 gochen 框架的可复用 IAM（Identity & Access Management）领域模块，提供：

- 用户 / 组织 / 角色 / 租户等基础域模型与 CRUD 能力
- JWT 认证（`AuthMiddleware` / `OptionalAuthMiddleware`）
- RBAC 授权（`RoleMiddleware` / `PermissionMiddleware`）
- 权限治理（启动期自动收集 required permissions + 可选严格模式）
- 后台菜单管理（`menu` 模块：落库 + 基于菜单自身规则的“导航可见性”过滤）

> 重要：菜单仅用于“导航可见性”，**不作为安全边界**。真正的安全边界应由服务端 API 的权限校验（如 `PermissionMiddleware`）保证。

---

## 快速接入（概念）

`gochen-iam` 以 gochen 领域模块方式提供能力：在 `module.go` 中实现 `server.IModule` 的 `Init(options)+Start(ctx)`，把 providers 注册、路由挂载与启动期校验都收敛在模块内部；上层应用只需要提供运行环境与 options 并调用模块入口。

- Providers 注册：`module.go`
- 路由注册器：`router/*.go`（具备 `RegisterRoutes/GetName/GetPriority` 方法）

上层应用（如 `alife`）通常只需要做两件事：

1. 通过 gochen 的模块级 `server.Server` 注册模块工厂，并在 ServerConfig 中配置：
   - BasePath 与全局中间件（挂载在 base group 上）
   - IAM 模块的挂载前缀与模块级中间件（例如默认 `"/iam"` 前缀）
2. 在路由层装配认证中间件（通常是全局中间件）：
   - `gochen-iam/middleware.AuthMiddleware`（必需鉴权）
   - 或 `gochen-iam/middleware.OptionalAuthMiddleware`（可选鉴权）

说明：
- 若你使用 `gochen-iam` 的 `Module.Start(ctx)` 挂载路由，模块会在挂载完成后自动执行严格权限字典校验（如开启）。
- 若你选择自行装配路由（不通过模块 Start），仍需在“所有 `PermissionMiddleware(...)` 都已执行注册”后手动调用 `middleware.ValidateStrictPermissionRegistry()`。

---

## 工程效率

- 代码检索/重复扫描：统一忽略 `.cache/.gocache`（仓库提供 `.ignore`；若你使用不读取 ignore 文件的工具，请在命令中显式加 `--ignore-dirs .cache,.gocache`）

## 认证（JWT）

### 中间件

- `middleware.AuthMiddleware(config)`：必需鉴权（无 token 直接拒绝）
- `middleware.OptionalAuthMiddleware(config)`：可选鉴权（无 token 放行；有 token 则必须有效，否则返回 401；有效则注入身份）

两者都会在验证 token 后将以下信息注入 `httpx.IRequestContext`：

- `user_id`
- `tenant_id`（可选）
- `roles`
- `permissions`
- `active_scope_id / active_scope_key / active_scope_type`

### 关键环境变量（AuthConfig）

`middleware.DefaultAuthConfig()` 会读取以下环境变量：

- `AUTH_SECRET`：必须提供
- `AUTH_ACCESS_TOKEN_TTL`：访问 token TTL（如 `24h`）
- `AUTH_ALLOW_QUERY_TOKEN`：是否允许从 query 读取 token（仅 dev/test 环境允许；生产强制禁用）
- `AUTH_REQUIRE_TENANT`：是否强制要求 `tenant_id`
- `AUTH_ALLOW_TENANT_QUERY`：是否允许从 query 读取 `tenant_id`
- `AUTH_TENANT_HEADER`：tenant header key（默认 `X-Tenant-ID`）
- `IAM_TENANT_MODE`：tenant 模式，支持 `fixed`（默认）/ `required`
- `IAM_FIXED_TENANT_ID`：默认 tenant ID（默认值 `default`）。当 `IAM_TENANT_MODE` 为空或 `fixed` 时使用

---

## 授权（RBAC）

### 中间件与辅助函数

- `middleware.RoleMiddleware(role)`
- `middleware.PermissionMiddleware(permission)`
- `middleware.AdminOnlyMiddleware()`：要求当前 active scope 内具备 `*:*:*`
- `middleware.PlatformScopeMiddleware()`：要求当前 token 的 active scope 为 `platform`
- `middleware.UserOnlyMiddleware()`：要求已登录用户

`PermissionMiddleware` 会在运行期校验权限，同时在启动期向 “required permissions registry” 注册权限码（见下节）。

### 权限码格式

权限码格式只支持一种：

- `type:resource:action`
- API 权限：`api:user:read`、`api:family:manage`
- 菜单权限：`menu:dashboard.home:view`
- 动作权限：`action:mcp:invoke`
- 仅支持“整段通配” `*`，例如 `api:*:*`、`api:task:*`、`menu:*:view`、`*:*:*`
- 不支持正则、半段模糊或混合写法（如 `api:ta*:read`、`^api:.*`）

---

## 权限治理：required permissions + 严格模式

### required permissions registry

在启动期调用到 `PermissionMiddleware("api:user:read")` 这类三段式权限时，会自动注册到内存 registry；也可以显式调用 `RegisterRequiredPermissionDefinitions(...)` 注册带 `type/resource/action/name/description` 元数据的权限定义。

- `middleware.RequiredPermissions()`：返回去重排序后的权限列表
- `middleware.RequiredPermissionsWithCallsites()`：附带 callsite（调试用途）
- `middleware.RequiredPermissionsWithRedactedCallsites()`：callsite 脱敏（仅保留 `file.go:line`）

### 严格权限字典（默认）

gochen-iam 默认启用严格权限字典：仅允许为角色写入“系统已声明的权限”（由 `PermissionMiddleware(...)` 在装配期自动收集）。

- 具体权限必须被 registry 显式注册
- 通配符权限必须至少能命中一条已注册权限（例如 `api:*:*`、`*:*:*`）

启动期校验在模块层执行：`gochen-iam/module.go` 的 `RegisterRoutes(ctx)` 会在路由装配完成后调用 `middleware.ValidateStrictPermissionRegistry()` 并通过 `error` 通道 fail-close。
当 registry 为空时，会直接阻止应用继续启动。

---

## 多租户（tenant）

默认约定 tenant 通过 HTTP Header `X-Tenant-ID`（或 `AUTH_TENANT_HEADER` 指定的 key）传入：

- `middleware.AuthMiddleware` / `OptionalAuthMiddleware` 会把 tenant 写入 `gochen/metadata.GetTenantID(ctx)`
- 业务侧可用 `middleware.RequireTenant(ctx)` / `middleware.RequireSameTenant(ctx, targetTenantID)` 做租户校验

也支持“固定 tenant / 单租户模式”：

- 设置 `IAM_TENANT_MODE=fixed`
- 可选设置 `IAM_FIXED_TENANT_ID=<your-tenant>`，默认 `default`
- 该模式下：
  - 请求无需显式传 `tenant_id`
  - 内部仍然保留 `tenant_id NOT NULL` 数据模型
  - CRUD / service / JWT / refresh 都会统一使用固定 tenant，而不是走“无 tenant”分支

若需要让 `system_admin` 以 platform scope 工作，不要依赖租户编码魔法值，而是显式创建一个 `is_platform=true` 的租户：

- 该租户的 `root_scope_id` 会自动指向正式的 `platform scope`
- 该租户下登录得到的 JWT `active_scope_type=platform`
- 当平台管理员要操作目标业务 tenant 时，请求头仍应显式携带目标 `X-Tenant-ID`；鉴权层会保留 `active_scope_type=platform`，但允许“platform token tenant != request tenant”
- `PlatformScopeMiddleware()`、跨租户 service guard、菜单/租户后台都会基于这个 active scope 生效
- 数据库层也会兜住“只能存在一个 platform tenant”，避免并发创建时出现双 platform

---

## 菜单模块（menu）

菜单模块用于后台系统的“导航结构”与“可见性配置”；默认完全由菜单自身的 permission 规则过滤。

### 数据模型（落库）

- `entity.MenuItem` → 表 `menu_items`
  - `code`：稳定唯一标识（unique）
    - 注意：当前删除为软删（`deleted_at`），且 `code` 不可复用；已删除记录仍会占用 `code`（避免治理/审计混乱）。
  - `parent_id`：父菜单（可为空）
  - `title/path/icon/type/order/route/component`
  - `hidden/disabled/published`
  - `any_of_permissions`：满足任一权限即可显示
  - `all_of_permissions`：必须满足全部权限才显示

### 可见性规则（下发 `GET /menus/me`）

当前实现逻辑：

1. 仅选择 `published=true` 的菜单项
2. 过滤：
   - `hidden=true` 或 `disabled=true`：直接过滤
   - `all_of_permissions`：必须全部满足
   - `any_of_permissions`：至少满足一个
   - 无请求上下文（`reqCtx=nil`）：仅展示无 permission 约束菜单
3. 父节点无权限但子节点可见时：保留父节点以承载子树

> 再强调：菜单不作为安全边界；即使菜单不可见，也必须在 API 层继续做权限校验。

### 防止菜单形成环（P0）

菜单是树形结构，必须防止：

- 自指：`parent_id == self_id`
- 回链：parent 链路最终回到自身

当前在服务层 `CreateMenuItem/UpdateMenuItem` 中做校验，拒绝写入会形成环的数据；同时 `sort/filter` 递归也做了防御性处理，避免历史脏数据导致栈溢出。

### 更新语义：request + 小型 FieldPatch（P1）

当前更新链路采用两层语义：

- router 层负责解释 HTTP patch 语义
- service 层继续接收常规 `UpdateMenuItemRequest`
- 只有少数字段（当前是 `parent_id`）会额外翻译成 `FieldPatch`

因此：

- `parent_id` 缺省（不传）→ 不更新
- `parent_id: null` → 解绑为根菜单
- `parent_id: 123` → 迁移到指定父菜单
- `path/icon/route/component` 传空字符串（如 `"path": ""`）→ 清空该字段
- `hidden/disabled/published` 传 `false`、`order` 传 `0` 也会被视为显式更新，而不是被“零值吞掉”

### HTTP 接口（router/menu.go）

当前接口分两类：

1) 当前用户可见菜单：

- `GET /menus/me`：需要已登录用户（`UserOnlyMiddleware`）

2) 管理端（当前设计：**仅允许 system_admin 管理菜单**）：

> 注意：管理端路由叠加了 `AdminOnlyMiddleware()` + `PermissionMiddleware("api:menu:read|write|publish")`。当前 `system_admin` 仍是角色边界，而其权限集合建议收敛为 `*:*:*`；这些 permission 仍承担“权限治理（required permissions）/审计”职责。
> 若未来希望非 system_admin 但具备菜单管理 permission 的角色接管菜单后台，可移除 `AdminOnlyMiddleware()`，仅保留对应 `PermissionMiddleware`。

- `GET /menus`（`api:menu:read`）
- `POST /menus`、`PUT /menus/:id`、`DELETE /menus/:id`（`api:menu:write`）
- `POST /menus/:id/restore`（`api:menu:write`，恢复软删）
- `DELETE /menus/:id/purge`（`api:menu:write`，物理删除）
- `POST /menus/:id/publish`、`POST /menus/:id/unpublish`（`api:menu:publish`）

对应权限码：

- `api:menu:read`
- `api:menu:write`
- `api:menu:publish`

---

## 数据库迁移 / 建表

本仓库本身不内置迁移脚本。典型做法是由上层应用在开发/测试环境通过 AutoMigrate 建表（例如 `alife/cmd/automigrate` 将 `&iamentity.Scope{}`、`&iamentity.MenuItem{}` 等模型加入列表）。

生产环境建议使用显式迁移脚本（避免 AutoMigrate 的不确定性）。

### 多租户 / Scope 字段迁移参考

当前版本不仅把 `users/groups/roles` 收口到 `tenant_id`，还引入了正式的 `scopes` 授权域模型：

- `tenants.root_scope_id -> scopes.id`
- `roles.namespace_scope_id -> scopes.id`
- `tenants.is_platform + tenants.platform_slot` 用于显式标记并唯一约束 platform tenant
- `groups.parent_key` 用于让“根组织同名唯一”在数据库层也能兜底

旧版本升级时，建议把“租户字段 backfill”和“scope 建模”一起完成。下面 SQL 以 PostgreSQL 为例，生产环境请按实际方言调整：

```sql
-- 1. 添加租户 / scope 相关列（先允许为空，便于分步回填）
ALTER TABLE users  ADD COLUMN tenant_id VARCHAR(64);
ALTER TABLE groups ADD COLUMN tenant_id VARCHAR(64);
ALTER TABLE roles  ADD COLUMN tenant_id VARCHAR(64);
ALTER TABLE groups ADD COLUMN parent_key BIGINT DEFAULT 0;
ALTER TABLE roles  ADD COLUMN namespace_scope_id BIGINT;
ALTER TABLE tenants ADD COLUMN is_platform BOOLEAN DEFAULT FALSE;
ALTER TABLE tenants ADD COLUMN platform_slot INTEGER;
ALTER TABLE tenants ADD COLUMN root_scope_id BIGINT;

-- 2. 创建 scopes 表（若尚不存在）
CREATE TABLE scopes (
    id BIGINT PRIMARY KEY,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP NULL,
    key VARCHAR(128) NOT NULL,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(32) NOT NULL,
    parent_id BIGINT NULL,
    path VARCHAR(1024) NOT NULL,
    depth INTEGER NOT NULL DEFAULT 0,
    description VARCHAR(500) NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active'
);

CREATE UNIQUE INDEX uq_scopes_key  ON scopes (key);
CREATE UNIQUE INDEX uq_scopes_path ON scopes (path);
CREATE INDEX idx_scopes_type      ON scopes (type);
CREATE INDEX idx_scopes_parent_id ON scopes (parent_id);

-- 3. 回填现有数据的 tenant_id / parent_key（根据实际租户策略调整）
UPDATE users  SET tenant_id = 'default' WHERE tenant_id IS NULL;
UPDATE groups SET tenant_id = 'default' WHERE tenant_id IS NULL;
UPDATE roles  SET tenant_id = 'default' WHERE tenant_id IS NULL;
UPDATE groups SET parent_key = COALESCE(parent_id, 0) WHERE parent_key IS NULL OR parent_key = 0;

-- 4. 初始化 platform scope（若不存在）
INSERT INTO scopes (id, version, created_at, updated_at, deleted_at, key, name, type, parent_id, path, depth, description, status)
SELECT
    1000000,
    0,
    NOW(),
    NOW(),
    NULL,
    'platform',
    'Platform',
    'platform',
    NULL,
    '/platform/',
    0,
    'Platform root scope',
    'active'
WHERE NOT EXISTS (
    SELECT 1 FROM scopes WHERE key = 'platform'
);

-- 5. 为历史 tenant 创建 tenant root scope（platform tenant 例外）
INSERT INTO scopes (id, version, created_at, updated_at, deleted_at, key, name, type, parent_id, path, depth, description, status)
SELECT
    1000000 + t.id,
    0,
    NOW(),
    NOW(),
    NULL,
    'tenant:' || t.key,
    t.name,
    'tenant',
    ps.id,
    '/platform/' || 'tenant:' || t.key || '/',
    1,
    t.description,
    'active'
FROM tenants t
JOIN scopes ps ON ps.key = 'platform'
WHERE COALESCE(t.is_platform, FALSE) = FALSE
  AND NOT EXISTS (
      SELECT 1 FROM scopes s WHERE s.key = 'tenant:' || t.key
  );

-- 6. 回填 tenant.root_scope_id / tenant.is_platform / tenant.platform_slot
--    若你的历史数据里已有明确的“平台租户”，请先把它标记为 is_platform = TRUE。
UPDATE tenants
SET root_scope_id = ps.id,
    platform_slot = 1
FROM scopes ps
WHERE COALESCE(tenants.is_platform, FALSE) = TRUE
  AND ps.key = 'platform';

UPDATE tenants
SET root_scope_id = ts.id
FROM scopes ts
WHERE COALESCE(tenants.is_platform, FALSE) = FALSE
  AND ts.key = 'tenant:' || tenants.key;

-- 7. 回填 role.namespace_scope_id（角色默认落在所属 tenant 的 root scope）
UPDATE roles r
SET namespace_scope_id = t.root_scope_id
FROM tenants t
WHERE t.key = r.tenant_id
  AND r.namespace_scope_id IS NULL;

-- 8. 设置 NOT NULL 约束
ALTER TABLE users  ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE groups ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE roles  ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE groups ALTER COLUMN parent_key SET NOT NULL;
ALTER TABLE roles  ALTER COLUMN namespace_scope_id SET NOT NULL;

-- 9. 删除旧的单列唯一索引（如存在），创建租户内复合唯一索引
DROP INDEX IF EXISTS idx_users_username;
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_groups_name;
DROP INDEX IF EXISTS idx_roles_name;
DROP INDEX IF EXISTS idx_group_name_parent_tenant;

CREATE UNIQUE INDEX idx_user_username_tenant ON users  (tenant_id, username) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_user_email_tenant    ON users  (tenant_id, email)    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_group_name_parent_tenant ON groups (tenant_id, name, parent_key) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_role_name_tenant     ON roles  (tenant_id, name)     WHERE deleted_at IS NULL;

-- 10. 创建 tenant_id / scope 相关索引
CREATE INDEX idx_users_tenant  ON users  (tenant_id);
CREATE INDEX idx_groups_tenant ON groups (tenant_id);
CREATE INDEX idx_roles_tenant  ON roles  (tenant_id);
CREATE INDEX idx_groups_parent_key ON groups (parent_key);
CREATE INDEX idx_roles_namespace_scope_id ON roles (namespace_scope_id);
CREATE INDEX idx_tenants_root_scope_id    ON tenants (root_scope_id);

-- 11. platform tenant 唯一哨兵（仅允许一个非 NULL platform_slot）
CREATE UNIQUE INDEX uq_tenants_platform_slot ON tenants (platform_slot);
```

> **注意**：
> - 若你在开发/测试环境依赖 AutoMigrate，请确保上层应用已把 `&iamentity.Scope{}` 纳入模型列表，而不只是 `User/Group/Role/MenuItem`。
> - 上述 SQL 以 PostgreSQL 语法为例；MySQL/SQLite 需调整 `BOOLEAN`、`NOW()`、`SET NOT NULL` 和条件索引语法。
> - `parent_key` 必须先完成 backfill，再切换唯一索引；否则根组织唯一性仍然会被 `NULL parent_id` 漏掉。
> - 如果历史数据里存在重复的“同租户同父节点同名”组织，建唯一索引前必须先清洗冲突数据。
> - 若准备切到“固定 tenant / 单租户模式”，建议把历史数据统一回填为 `IAM_FIXED_TENANT_ID` 对应的值。
> - `platform_slot` 是“全库最多一个 platform tenant”的唯一哨兵。非 platform tenant 应保持 `NULL`；platform tenant 建议固定回填为 `1`。
> - `namespace_scope_id` 目前默认回填为租户 root scope；后续若角色要下沉到更细粒度 scope，再单独演进。
> - 更完整的授权域设计背景，可参考 `docs/domain-authorization-design.md`。

---

## 开发与验证

- 格式化：`gofmt -w ./...`
- 测试：`go test ./...`
