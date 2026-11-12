# gochen-iam

`gochen-iam` 是基于 `gochen` 的可复用 IAM（Identity & Access Management）领域模块，当前已经切换到分层授权最终设计：

- 认证采用两阶段登录：`Authenticate -> ActivateScope`
- 授权运行时统一围绕 `Principal.ActiveScopeID`
- 资源归属统一围绕 `managed_scope_id` / `namespace_scope_id`
- 查询边界统一围绕 `DataScope.VisibleScopeIDs`
- 最终写边界统一围绕 `AuthzDecision -> spec.Spec`（写规约）
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

- `tenant_id` 仍保留为业务字段，用于租户内唯一性与请求归一化（例如 email/name 在租户内唯一、同租户关联查询过滤）
- 授权判定层使用 `authz.Resource.TenantID` 结构化字段承载租户归属语义，不再从 `owner_id` 字符串前缀推断
- 真正的授权边界统一由 `managed_scope_id` / `namespace_scope_id` 与 `scope_visibility_map` 表达
- 平台级资源（scope / tenant / menu）通过 `authz.Resource.GlobalScope=true` 显式标记，与"未填充 managed scope"语义完全分离
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
2. 如需记录拒绝审计，在组合根把 `AuditMiddleware(logger, sink)` 挂在最外层（早于模块内默认 AuditMiddleware）；最外层 recorder 优先，logger/sink 按请求实例传递，不使用包级全局状态
3. 在 HTTP 层挂载 `AuthMiddleware(...)` 或 `OptionalAuthMiddleware(...)`
4. 在业务接口使用 `PermissionMiddleware(...)`、`AdminOnlyMiddleware()`、`PlatformScopeMiddleware()` 等入口 guard
5. 通过标准 repo / service / CRUD builder 使用自动注入的数据边界与写边界

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

应用在配置加载阶段调用 `config.ApplyEnvOverrides`，再用 `config.NewAuthConfig(runtimeConfig, environment)` 构造认证配置，通过 `iam.ModuleAuthConfig` 注入模块，并把同一配置传给中间件和 `router.NewAuthRoutesWithConfig`。认证配置与租户策略在运行期不再读取进程环境，传入 `nil` 认证配置会被拒绝。

`config.ApplyEnvOverrides` 支持：

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
- 非 HTTP 调用通过 `tenant.WithPolicy(ctx, policy)` 绑定单租户策略；未绑定策略时按租户隔离处理，要求上下文提供 tenant ID
- 权限目录调用点仅由 `router.PermissionCatalogOptions.ExposeCallsites` 显式控制，不再读取 `AUTH_EXPOSE_PERMISSION_CALLSITES`

## 授权（RBAC + Scope）

### 中间件与辅助函数

- `middleware.RoleMiddleware(role)`
- `middleware.PermissionMiddleware(permissionSpec)`
- `middleware.AdminOnlyMiddleware()`
- `middleware.PlatformScopeMiddleware()`
- `middleware.UserOnlyMiddleware()`

说明：

- `AdminOnlyMiddleware()` 要求当前 active scope 内具备 `*:*:*`
- `PlatformScopeMiddleware()` 要求当前 active scope kind 为 `platform`
- `PermissionMiddleware(...)` 只接受结构化 `PermissionSpec`，既做运行期校验，也会把权限注册进 required permissions registry

### 权限码格式

权限码统一为三段式：

- `resource:type:action`
- 例如：`user:api:read`、`menu:api:publish`、`dashboard.home:menu:view`

仅支持整段通配：

- `*:api:*`
- `*:menu:view`
- `*:*:*`

权限以 JSON 数组存放在 `roles.permissions`、`menu_items.any_of_permissions` 与 `menu_items.all_of_permissions`。
当前各项目均无存量部署，建库基线、种子数据及调用方直接使用 `resource:type:action`，不保留历史 `type:resource:action` 转换链。
通配符也按段定位：例如 `*:api:*` 表示任意资源的 API 权限，不能交换为 `api:*:*`。

### 权限目录装配（strict permission registry）

角色授权校验（`validatePermissions`）与权限目录接口都以 strict permission registry 为事实源。路由装配期的 `PermissionMiddleware(...)` **只登记该路由实际拦截的权限码**，因此完整目录必须显式登记：

- IAM 自身目录：`iam.NewModule(...)` 内部调用 `service.RegisterIAMPermissionCatalog()` 自动完成；
- 下游模块目录：由应用在创建 authz registry 时安装同步钩子，各模块经 `Extension(authz.Catalog{...})` 声明的权限会自动镜像进来，模块侧无需重复注册。

```go
registry := authz.NewRegistry()
if err := iamservice.InstallIAMPermissionCatalog(registry); err != nil {
    return err
}
app := quick.New(
    config.WithCatalogRegistrar(authz.NewCatalogRegistrar(registry)),
    config.WithModuleCapabilities(iam.ModuleAuthConfig(authConfig)),
)
app.Modules(iamModuleCtor)
app.Group("").Use(iammw.AuthMiddleware(authConfig)).Modules(workflowModuleCtor)
err := app.Run(ctx)
```

上述入口使用 `gochen-runtime/quick` 与 `gochen-runtime/host/config`。IAM 单独注册，内部区分登录和受保护路由；业务模块在认证分组中继承 middleware。默认前缀按模块 ID 推导，不再维护按 ID 索引的 HTTP 配置表。

每个应用独立创建一份 `*iammw.AuthConfig`，所有认证中间件与 `ModuleAuthConfig` 共用该指针；若在 DI 注册配置，也必须是同一实例。IAM 在启动期为该配置绑定 `ContextResolver`，启动后不得修改配置。独立使用中间件或认证路由时须显式注入解析器，不再支持进程级全局安装或隐式回退。

漏装同步钩子的后果：下游模块的 `xxx:menu:view` 等未挂中间件的权限码不会进入 registry，授予角色时会被判为"未知权限"。

## 查询与写入边界

User 标准 HTTP 列表使用构造期固定的 User／Group／Role 三资源命令。Core 保留查询与分页规范化，实际用户查询在分页前执行条件，关联只接受本页真实用户 ID，并分别执行组／角色条件。分页计数使用同一用户声明，保留数值可信用户、manage 加 read、platform／tenant 与单租户语义；普通列表保留既有全部角色绑定投影。真实 REST GET／HEAD 绑定、SQLite 过滤、实际 GORM 拒绝零查询及 Runtime Lite 独立条件／能力生命周期已验证。剩余权限查询及完整项目门禁继续迁移。

标准创建及批量创建使用同一固定 UserRepo 的 Core Application，沿用数值可信用户、manage 加 write 及原授权域／单租户规则。请求携带 Groups／Roles 时返回 Validation，关联使用分配入口；租户／归属／管理范围由可信上下文填写，bcrypt 和事务保持。真实标准 CRUD 子集为 13 个 HTTP 入口（10 declared／3 协议 explicit_allow／0 invalid），包含两条创建入口。SQLite 验证关系拒绝、归属保护、密码及整批回滚；真实 GORM 验证权限拒绝前零访问与第二笔创建故障回滚。`NewUserRoutes` 仅接收实际声明服务并返回错误。

Tenant 删除核对持久化 RootScopeID 指向的实际 Scope：ID 一致、key=tenant:<当前租户 Key> 且 type=tenant；失联或漂移返回 Validation 并提示先修复。删除前复核，实际 Scope 软删条件再次绑定 key/type 及版本。同一事务保持租户、根范围与可见性投影的回滚；标准及批量 HTTP 的实际 SQLite 失败注入已验证。Tenant CRUD 的附属资源声明和响应治理继续迁移。

标准单条读取、更新及单条／批量删除使用构造期固定的实际 UserRepo。写入命令通过 `Options.CommandGrant` 复用主资源判定，Core 校验仓储、动作、目标、身份和命令生命周期。更新在 Core 事务内冻结当前实体，密码及归属治理复用该前像；单次调用完成一次主资源判定与一次当前实体读取。保留空密码、bcrypt 输入／加密、版本与维度保护、无变化跳过及既有软删除。实际 GORM 验证拒绝零访问、单次当前实体读取、第二笔写故障时整批更新／删除回滚；Lite 验证真实 REST、单次判定、版本冲突、范围拒绝及能力撤销。旧 User update／delete hooks 已脱离生产调用，保留待专门清理。

Group 普通服务与 HTTP CRUD 同样通过 `CommandGrant` 复用主资源判定，更新钩子复用 Core 事务前像。父组织、完整名称目录、子树、删除引用和 Tenant／RootScope 保持各自声明能力及条件；子树改动在首次写入前完成逐节点检查，并与主组织写入一同回滚。回归覆盖主资源单次判定、当前实体单次读取、旧版本拒绝、动作／目标边界及命令结束后撤销。

`NewUserService` 返回服务及错误，构造时要求实际 User／Group／Role 仓储。`SearchUsers` 和 `UsersByStatus` 分别使用三个资源的固定命令，沿用 `user:api:read`。主查询先执行租户、范围与软删除条件，再筛选并应用数量限制；组、角色关联只接受本次可信返回的用户 ID，各自执行条件。三资源复用一次租户根覆盖事实，System 保留既有覆盖要求。其余 User/Auth 入口继续迁移。

`UserRoles` 与 `UserGroups` 使用普通／HTTP 两套固定资源命令。先读取条件内的主用户，再读取其关联；用户角色仅返回生效绑定，并按已授权角色的真实 NamespaceScopeID 读取 namespace。用户所属组、父组、成员与默认角色分别执行条件，保留原响应结构且完整返回超过 1000 条的关联。启用、停用、锁定、解锁使用注册的真实用户 Fact，Core 复用同一读取保护归属和版本，范围外写保持 Forbidden。

`AssignToGroup`／`RemoveFromGroup` 使用用户写和目标组读的两资源命令，沿用 `user:api:write`。可信 Fact 提供实际用户／组，条件独立执行，范围外保持 Forbidden；事务内复核两者的租户、归属与版本后写关联，重复添加／移除保持幂等，批量加入保留逐用户部分成功响应。UserRepo 两个关联写方法分别接收用户条件与组条件，目标条件在同一事务内检查。

`AssignRole`／`AssignRoleBinding` 使用实际 User、基础 Role、绑定模型、Scope、visibility 及单租户 Tenant／RootScope 能力，沿用 `user:api:write` 和平台角色约束。用户／角色条件独立执行；绑定与覆盖投影要求完整条件，单租户根能力仅在该分支读取。事务内复核用户／角色版本、状态、归属及 grant 覆盖，显式 scope 直接传给 UserRepo.AssignRole。单租户固定租户根，nil／非正值沿用默认值，变更原请求指针保持冻结意图。

`RemoveRole` 分别声明用户、基础角色及绑定，事务内复核租户／归属／版本后，删除该真实 user/role 的全部绑定，包含范围外 grant。`RemoveRoleBinding` 先取得已授权用户的真实绑定快照，再授权其角色及范围；事务内复核 user/role/grant/status 后精确删除。绑定详情的角色存在性、grant 与可见 namespace 查询限定本次真实关联，保留已删除／不可见角色占位、展示及单租户祖先覆盖。原生绑定／范围目录读取要求完整条件；真实 SQLite、HTTP、1002 条投影及能力／回滚验证已通过。

`NewUserRoutes` 接收实际声明服务并返回路由及错误。上述查询、状态、组写、角色分配／删除及绑定详情保留数值可信用户、manage 加 read／write、platform／tenant 授权域及单租户豁免。同一服务器去重后的实际自定义 HTTP 子集共 26 个入口：16 declared、10 preflight explicit_allow、0 invalid，组／角色／绑定查询与写入各共用 OPTIONS；其余 User/Auth 入口及完整项目门禁继续待迁移。

`UserProfile`／`UpdateProfile`／`ChangePassword` 使用固定的自助资源命令，可信普通用户仅可操作本人，System 可在当前租户指定用户。`user:self:read/write` 表达内部身份检查；自助入口通过可信 Principal 取得用户 ID。资料组／角色只读取该真实用户的同租户关联，保留范围外展示、inactive 绑定及既有 JSON 结构；邮箱占用只返回请求邮箱的同租户存在性。资料和密码写入保留显式 DataScope（含 System）、旧密码校验、bcrypt 及归属／版本原子保护。真实自助 HTTP 共 6 个入口（4 declared／2 协议 explicit_allow／0 invalid）；完整 User 路由为 50（30 declared／17 explicit_allow／3 invalid），权限汇总和检查继续待迁移。SQLite、1002 条资料关联、零查询拒绝、真实 HTTP 与受管理能力边界已验证。

`NewRoleService` 返回服务及错误，构造时固定实际 Role／User／Group 仓储与可选 ScopeAuthorizer。`RoleStatistics` 和 HTTP 统计使用同一 Role 来源的普通／HTTP 强类型命令，沿用 `role:api:read`、租户根覆盖及原 DataScopeResolver：显式范围优先，未绑定时从可信 ActiveScopeID 推导，System 也保留显式范围和实际根覆盖规则。HTTP 另检查数值可信身份、manage 与 platform／tenant 及单租户豁免。授权条件在三次计数和每一页状态投影前执行，统计不预加载关联。统计 HTTP 子集为 3 = 2 declared / 1 explicit_allow / 0 invalid；完整 Role 路由仍有未接入入口，门禁继续拒绝，目录、关联与 CRUD 继续迁移。

`ActivateRole`／`DeactivateRole` 的普通及 HTTP 入口使用固定 Role Fact 和 CommandRepository，保留 `role:api:write`、原租户／范围与 System 规则；HTTP 与统计共享数值身份、manage、授权域及单租户约束。系统角色可启用，停用返回 Validation；范围、归属和版本在实际写入中保护。`RemovePermission` 已接入相同命令，现有 `PermissionArray.Value` 的返回签名缺少标准 `driver.Valuer` 契约，导致框架更新遗漏权限字段，实际持久化回归仍失败。签名修正与完整 Role 迁移继续待完成；进度见工作区实施契约。

`SystemRoles` 使用构造期固定的 Role／namespace 两资源命令，沿用 `role:api:read`、租户根覆盖及同租户全部系统角色目录，保留 inactive 角色展示。HTTP 另要求数值可信身份、manage、platform／tenant 及单租户豁免。角色条件在每页查询前执行，namespace 独立条件只查询已读取角色的真实 NamespaceScopeID，软删 namespace 保持缺失，响应保持无用户／组预加载。两资源复用一次覆盖事实，完整 1002 条目录、独立条件／可信来源／身份／生命周期及实际 HTTP 已验证。该 HTTP 子集为 3 = 2 declared / 1 explicit_allow / 0 invalid；完整 Role 根为 39 = 17 declared / 13 explicit_allow / 9 invalid，剩余入口继续阻断门禁。

### 查询

repo / orm 默认围绕资源归属字段注入边界：

- `users.managed_scope_id`
- `groups.managed_scope_id`
- `roles.namespace_scope_id`

运行时流程：

1. 从 access token 恢复 `ActiveScopeID`
2. 由 `AuthContextResolver` / `ScopeAuthorizer` 解出 `VisibleScopeIDs`
3. repo 把边界翻译成 `managed_scope_id in (...)` 或等价 join `scope_visibility_map`

单租户模式不会把 platform scope 自动并入 tenant token 的 `VisibleScopeIDs`。关联读取也会对目标 user/group/role 执行完整资源授权；需要访问 platform-owned 记录时，调用方必须显式切换到 platform active scope，否则返回 `Forbidden`。

### 写入

所有正式写操作最终都围绕显式 `spec.Spec` 写规约落库：

- service 先做 `Authorize(...)`
- 将 allow 决策投影成 `spec.Spec`
- repo 在最终 `INSERT / UPDATE / DELETE` 处合并规约并校验：
  - 资源 ID
  - `managed_scope_id`
  - `revision/version`（乐观锁）

这意味着：

- 不能只在 router/service 做前置 tenant 判断后直接写库
- 不能依赖隐式 context 猜测最终写边界
- `RowsAffected = 0` 不会被当成“静默成功”

## 租户管理（tenant）

`NewTenantRoutes` 接收实际 Tenant/User/Group/Role/Scope 仓储并返回路由及错误，构造期固定完整资源声明并核对同一事务数据源。标准单条和批量 CRUD 使用 Core 的事务、版本与软删保护，保留可信数值用户、平台授权域、单租户豁免及 `tenant:api:read/write/delete`；启停与修复沿用各自声明。

创建将根范围、可见关系和租户引用声明为完整目录能力，清除客户端根引用，同事务补齐并回读真实版本。更新通过独立的受条件保护快照保留根引用。删除仅允许 inactive、无用户／组织／角色及根子范围占用的租户，用户占用包括当前租户和归属租户；实际根的 ID、`key=tenant:<Key>`、`type=tenant` 必须一致，漂移时提示先修复。根软删及可见关系重建与租户删除同事务回滚。

列表、详情及更新响应在请求命令内生成删除治理与根健康投影，包装器执行纯转换，保留现有 JSON 格式。各目录能力在主资源访问前核对完整条件；租户关联与根引用使用本次可信快照，普通资源条件先于分页和计数。完整 Tenant HTTP 验证为 19 个实际入口：13 declared、6 protocol explicit_allow、0 invalid；这项结果覆盖 Tenant 模块。

## 组织管理（group）

`NewGroupService` 构造期编译关联写、统计、组树、四类查询及删除命令，并返回服务及错误；`NewGroupRoutes` 要求同一声明服务并返回错误。添加、移除成员及默认角色、批量添加成员分别声明组写能力和用户／角色读能力，沿用 `group:api:write`。关联目标从实际基础仓储读取，组与目标分别执行授权条件，在同一事务中复核租户、管理范围、归属与版本后写入。

批量操作在第一笔关联写入前检查全部目标；任一失败整批回滚，成功数归零，保留逐项错误响应。组统计分别声明组、用户、角色三个资源，计数及层级／状态统计在查询前执行各自条件。组树使用组记录及成员计数两个资源，按授权组分页确定成员统计的目标，条件先于 JOIN 和聚合；保留层级与排序并返回全部页面。HTTP 保留可信数值用户、platform／tenant 或单租户授权域、manage 加 write／read 的要求；入口检查先于可能读取可信范围事实的策略。

根组、按层级、组成员和默认角色查询分别声明组、用户、角色及用户组资源，关联查询在 JOIN 和实体分页前落实各自条件。namespace 读取由已授权角色的真实 NamespaceScopeID 派生，父组读取限定已读组的 ParentID。查询保留既有返回结构，完整返回超过 1000 条的组及成员。

`DeleteGroup` 和 `ValidateDelete` 声明组及其子组／成员存在性能力，沿用 `group:api:delete`。存在性由已授权组派生，只返回同租户结果；同租户全部关联均阻止删除，包含调用者范围外记录。删除在同一事务中完成检查与版本保护的软删，失败回滚。

创建、更新和删除统一通过固定多资源门面执行，Core 承担事务、版本及维度保护。创建声明父组、同租户名字存在性，以及缺范围时真实 Tenant／RootScope 读取；移动时沿真实 ParentID 遍历完整子树，每个节点先取得独立写能力，同事务更新路径与层级。完整 Group 实际 HTTP 清单为 39 个入口（27 declared / 12 explicit_allow / 0 invalid），包含标准及批量 CRUD、五个关联写与全部查询。旧私有 CRUD hooks 已脱离生产调用，保留待专门清理。

## 多租户（tenant）

`NewTenantService` 返回服务及错误，构造期固定普通七个动作与启用、停用、修复三个 HTTP 命令，并要求实际 Tenant／Scope 提供方一致。创建和修复分别声明租户、根范围、可见关系及租户引用，完整目录能力预检通过后在同一事务内执行；编码检查、普通更新及完整分页列表通过受管理端口落实条件与版本。根范围能力校验冻结租户的 ID、编码、名称、描述、状态、根引用及版本，包含根引用指针的独立复制。HTTP 命令保留可信数值身份、平台域和单租户豁免。

当前已验证普通服务与上述三个 HTTP 动作：拒绝前零资源访问、能力动作／目标／身份／生命周期、1001 条完整分页及软删过滤、创建后持久化版本，以及根范围／可见关系／租户引用故障回滚。标准及批量 HTTP CRUD 和响应治理的完整多资源迁移仍待完成；删除的根范围归属校验等待用户裁定，全项目门禁尚未完成。

Scope 治理服务使用强类型多资源 Command。`NewScopeService` 构造期要求 scope、tenant、role、user、group 的实际仓储并返回错误；`NewScopeRoutes` 接收同一声明服务。树、可见性及各类引用投影分别取得能力，全部授权和完整目录条件检查通过后执行业务。创建、删除和可见性重建保持同一事务，写动作复用一次平台覆盖事实；平台根初始化由 `EnsurePlatformScope` 承担。

HTTP 的列表、可见性、创建、更新、启停、修复和删除分别绑定声明命令。启用入口注册表时，真实 nethttp 清单共 16 个入口：10 declared、6 框架预检 explicit_allow、0 invalid。单租户 HTTP 读取沿用现有平台检查语义；写入继续要求实际 active scope 覆盖平台根，System 同样执行覆盖约束。全项目门禁仍需其余 IAM 入口完成迁移。

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

- 可信数值用户、既有平台授权域及 `menu:api:manage`
- 读取另要求 `menu:api:read`；写入、恢复及物理删除要求 `menu:api:write`；发布要求 `menu:api:publish`
- 单租户模式保留 HTTP 授权域检查的豁免；普通主体仍须通过平台资源约束，System 仍须提供数值用户

`NewMenuService` 返回服务及错误，构造期固定实际菜单仓储和普通/HTTP 两个声明 Application。标准 CRUD 使用私有领域钩子，在已授权的完整全局目录内检查父链和 code 唯一性；发布、恢复、物理删除、同步及完整列表使用资源 Command。同步分别取得更新、创建和关系目录读取能力，全部授权后在同一事务内执行，失败整批回滚。

`NewMenuRoutes` 接收同一服务并返回错误。`MyMenuTree(ctx)` 的已发布读取与权限过滤共用可信上下文。实际 nethttp 清单为 26 个入口（15 declared / 11 explicit_allow / 0 invalid），包含导航及框架 HEAD/OPTIONS；缺绑定阻断门禁。相关权限、能力边界、SQLite 回滚及 HTTP 生命周期测试通过。

`menu:api:manage` 已纳入模块权限目录，保持原管理路由的权限定义。`RegisterPermissionCatalogRoute` 在路由组提供 EntryRegistry 时登记内存权限元数据放行依据，保留宿主中间件与调用点脱敏开关；真实 GET/HEAD/OPTIONS 共三个入口均有效，绑定失败时停止注册。

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

角色普通服务与 HTTP 基础 CRUD 共用 `roleCRUDApplication`：每次调用登记角色、名称完整性目录、namespace 及用户/组引用等实际资源，并把受管理能力装入私有治理 Hooks。Core 继续负责事务、版本和受保护字段。`RoleService.HTTPApplication()` 提供同源执行绑定，覆盖批量与自定义 Execute 方法；REST 启用编译计划的 FastDeny，在初始实体读取前拒绝缺少动作权限的请求。

名称唯一性和删除引用检查使用已授权角色与可信租户边界内的完整集合。调用方列表范围之外的重名、用户引用或组引用仍会阻止写入。克隆和追加权限复用相同治理能力；组关联分别授权角色和组织，并在同一事务中检查冻结的版本、归属和状态。

角色目录读取通过独立条件查询角色聚合，再按实际返回的 namespace ID 读取投影。`RoleRepo.Get` 读取角色聚合；namespace 展示投影由应用的声明能力提供。`RoleService.CheckPermission` 要求 role read 权限与用户目标可见性，随后通过该用户及实际组关联派生完整有效权限，保留生效绑定、角色状态及租户边界。

在本仓库目录下运行：

```bash
go test ./... -count=1
(cd ../gochen && go test ./... -count=1)
(cd ../alife && go test ./internal/progress/... ./internal/shop/... ./cmd/migrate -count=1)
```

工程约定：

- 默认忽略 `.cache/.gocache`
- Go 代码修改后执行 `gofmt`
- 不保留兼容层，不维持双语义路径
