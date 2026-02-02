# gochen-iam

`gochen-iam` 是基于 gochen 框架的可复用 IAM（Identity & Access Management）领域模块，提供：

- 用户 / 组织 / 角色 / 租户等基础域模型与 CRUD 能力
- JWT 认证（`AuthMiddleware` / `OptionalAuthMiddleware`）
- RBAC 授权（`RoleMiddleware` / `PermissionMiddleware`）
- 权限治理（启动期自动收集 required permissions + 可选严格模式）
- 后台菜单管理（`menu` 模块：落库 + 基于权限的“导航可见性”过滤）

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
- `middleware.OptionalAuthMiddleware(config)`：可选鉴权（有 token 则注入身份，无 token 也放行）

两者都会在验证 token 后将以下信息注入 `httpx.IRequestContext`：

- `user_id`
- `tenant_id`（可选）
- `roles`
- `permissions`

### 关键环境变量（AuthConfig）

`middleware.DefaultAuthConfig()` 会读取以下环境变量：

- `AUTH_SECRET`：必须提供
- `AUTH_ACCESS_TOKEN_TTL`：访问 token TTL（如 `24h`）
- `AUTH_ALLOW_QUERY_TOKEN`：是否允许从 query 读取 token（仅 dev/test 环境允许；生产强制禁用）
- `AUTH_REQUIRE_TENANT`：是否强制要求 `tenant_id`
- `AUTH_ALLOW_TENANT_QUERY`：是否允许从 query 读取 `tenant_id`
- `AUTH_TENANT_HEADER`：tenant header key（默认 `X-Tenant-ID`）

---

## 授权（RBAC）

### 中间件与辅助函数

- `middleware.RoleMiddleware(role)`
- `middleware.PermissionMiddleware(permission)`
- `middleware.AdminOnlyMiddleware()`：等价于 `RoleMiddleware("system_admin")`
- `middleware.UserOnlyMiddleware()`：要求已登录用户

`PermissionMiddleware` 会在运行期校验权限，同时在启动期向 “required permissions registry” 注册权限码（见下节）。

### 权限码格式

权限码格式为：`resource:action`（例如 `user:read`、`menu:publish`）。

---

## 权限治理：required permissions + 严格模式

### required permissions registry

在启动期调用到 `PermissionMiddleware("a:b")` 时，会自动注册到内存 registry：

- `middleware.RequiredPermissions()`：返回去重排序后的权限列表
- `middleware.RequiredPermissionsWithCallsites()`：附带 callsite（调试用途）
- `middleware.RequiredPermissionsWithRedactedCallsites()`：callsite 脱敏（仅保留 `file.go:line`）

### 严格权限字典（默认）

gochen-iam 默认启用严格权限字典：仅允许为角色写入“系统已声明的权限”（由 `PermissionMiddleware(...)` 在装配期自动收集）。

启动期校验在模块层执行：`gochen-iam/module.go` 的 `RegisterRoutes(ctx)` 会在路由装配完成后调用 `middleware.ValidateStrictPermissionRegistry()` 并通过 `error` 通道 fail-close。
当 registry 为空时，会直接阻止应用继续启动。

---

## 多租户（tenant）

约定 tenant 通过 HTTP Header `X-Tenant-ID`（或 `AUTH_TENANT_HEADER` 指定的 key）传入：

- `middleware.AuthMiddleware` / `OptionalAuthMiddleware` 会把 tenant 写入 `IRequestContext.GetTenantID()`
- 业务侧可用 `middleware.RequireTenant(ctx)` / `middleware.RequireSameTenant(ctx, targetTenantID)` 做租户校验

---

## 菜单模块（menu）

菜单模块用于后台系统的“导航结构”与“可见性配置”，可绑定权限条件进行过滤。

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
   - 无请求上下文（`reqCtx=nil`）：仅展示无权限约束菜单
3. 父节点无权限但子节点可见时：保留父节点以承载子树

> 再强调：菜单不作为安全边界；即使菜单不可见，也必须在 API 层继续做权限校验。

### 防止菜单形成环（P0）

菜单是树形结构，必须防止：

- 自指：`parent_id == self_id`
- 回链：parent 链路最终回到自身

当前在服务层 `CreateMenuItem/UpdateMenuItem` 中做校验，拒绝写入会形成环的数据；同时 `sort/filter` 递归也做了防御性处理，避免历史脏数据导致栈溢出。

### 更新语义：支持“清空字符串字段”（P1）

`UpdateMenuItemRequest` 对 `path/icon/route/component` 使用 `*string`，因此：

- 字段缺省（不传）→ 不更新
- 传空字符串（如 `"path": ""`）→ 清空该字段

### HTTP 接口（router/menu.go）

当前接口分两类：

1) 当前用户可见菜单：

- `GET /menus/me`：需要已登录用户（`UserOnlyMiddleware`）

2) 管理端（当前设计：**仅允许 system_admin 管理菜单**）：

> 注意：管理端路由叠加了 `AdminOnlyMiddleware()` + `PermissionMiddleware("menu:*")`。由于 system_admin 天然拥有全部权限，`menu:*` 更偏向“权限治理（required permissions）/审计”用途。
> 若未来希望非 system_admin 但具备 `menu:*` 权限的角色管理菜单，可移除 `AdminOnlyMiddleware()`，仅保留 `PermissionMiddleware`。

- `GET /menus`（`menu:read`）
- `POST /menus`、`PUT /menus/:id`、`DELETE /menus/:id`（`menu:write`）
- `POST /menus/:id/restore`（`menu:write`，恢复软删）
- `DELETE /menus/:id/purge`（`menu:write`，物理删除）
- `POST /menus/:id/publish`、`POST /menus/:id/unpublish`（`menu:publish`）

对应权限码：

- `menu:read`
- `menu:write`
- `menu:publish`

---

## 数据库迁移 / 建表

本仓库本身不内置迁移脚本。典型做法是由上层应用在开发/测试环境通过 AutoMigrate 建表（例如 `alife/cmd/automigrate` 将 `&iamentity.MenuItem{}` 加入 models 列表）。

生产环境建议使用显式迁移脚本（避免 AutoMigrate 的不确定性）。

---

## 开发与验证

- 格式化：`gofmt -w ./...`
- 测试：`go test ./...`
