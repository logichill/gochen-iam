# 域授权设计（已实现版）

本文档描述 `gochen-iam` 当前已经落地的授权实现，并与 `/home/alex/data/priv/project/gochen/docs/architecture/layered-authz-framework.md` 保持一致。

## 1. 设计结论

当前实现已经硬切到以下模型：

- tenant 与 scope 分离
- platform 是 scope，不是 tenant
- 登录采用两阶段：`Authenticate -> ActivateScope`
- access token 仅保留最小语义：`user_id + active_scope_id + binding_version + permissions`
- 查询边界统一围绕 `managed_scope_id` / `namespace_scope_id`
- 作用域可见性统一围绕 `scope_visibility_map`
- 最终写边界统一围绕 `AuthzDecision -> WriteConstraint`

以下历史方案已废弃：

- `platform tenant`
- `tenants.is_platform`
- `tenants.platform_slot`
- 基于 `scope_type / scope_code` 的 repo 等值过滤
- 基于 tenant 推断 active scope 的登录逻辑

## 2. 当前数据模型

### 2.1 Scope 树

系统维护一棵正式授权树：

- `scopes`
- `scope_visibility_map`

语义：

- `platform` 是唯一根节点
- 每个 tenant 通过 `tenants.root_scope_id` 连接到授权树
- `scope_visibility_map(viewer_scope_id, target_scope_id, distance)` 是 scope 树的预展开投影

### 2.2 Tenant

`tenants` 当前只保留业务语义：

- `key`
- `name`
- `status`
- `root_scope_id`

tenant 不再承担：

- platform 模拟
- active scope 推断
- 授权覆盖关系表达

### 2.3 User

`users` 当前关键字段：

- `tenant_id`
- `home_tenant_id`
- `home_scope_id`
- `managed_scope_id`
- `owner_id`

语义：

- `home_scope_id` 表示主体默认归属 scope
- `managed_scope_id` 表示用户资源本身归哪个管理范围负责
- 用户不是“平台用户 / 租户用户”两种类型，权限全部来自 binding

### 2.4 Role

`roles` 当前关键字段：

- `tenant_id`
- `namespace_scope_id`
- `owner_id`
- `permissions`

语义：

- 角色定义落在某个 namespace scope 下
- `platform_admin` 是 platform scope 下的角色
- `tenant_admin` 是 tenant root scope 下的角色

### 2.5 UserRoleBinding

`user_role_bindings` 当前关键字段：

- `user_id`
- `role_id`
- `grant_scope_id`
- `status`

语义：

- 用户通过 binding 在某个 scope 内获得某个角色
- 同一用户可以同时拥有多个 scope 下的多个 binding
- 登录后进入哪个工作态，是 active scope 选择问题，而不是 tenant 推断问题

## 3. 运行时模型

当前运行时固定围绕五个核心概念组织：

1. `Principal`
   - 表达当前是谁在操作
   - 关键字段：`SubjectID`、`ActiveScopeID`、`Permissions`
2. `Resource`
   - 表达资源归哪个管理范围负责
   - 关键字段：`ManagedScopeID`、`OwnerID`、`Revision`
3. `AuthzDecision`
   - 表达 allow / deny 与授权命中的资源快照
4. `DataScope`
   - 表达当前默认可见的 scope 集合
   - 关键字段：`ActiveScopeID`、`VisibleScopeIDs`
5. `WriteConstraint`
   - 把 allow 决策投影成最终写库边界

## 4. 两阶段登录

### 4.1 Authenticate

第一阶段只做：

- 用户名/密码校验
- 读取当前用户有效 binding
- 聚合出 `available_scopes`
- 生成短期 `activation_token`

此阶段不再签发最终 access token。

### 4.2 ActivateScope

第二阶段显式输入：

- `activation_token`
- `scope_id`

系统会：

1. 校验该 scope 是否在第一阶段返回的候选集合内
2. 重新构造当前 active scope 下的会话快照
3. 签发最终 access token

### 4.3 Access Token

当前 access token claim 固定为：

- `user_id`
- `active_scope_id`
- `binding_version`
- `permissions`

不会再持久化：

- `active_scope_code`
- `active_scope_type`
- `platform tenant` 派生语义

### 4.4 运行时上下文恢复

`AuthMiddleware` 验证 token 后，不直接信任 token 中的冗余上下文，而是：

1. 取出 `active_scope_id`
2. 通过 `AuthContextResolver` / `ScopeAuthorizer` 回源解析：
   - `ActiveScopeKind`
   - `VisibleScopeIDs`
3. 将 `Principal`、`DataScope`、`tenant_id` 一起注入请求上下文

## 5. 查询模型

所有受控资源查询统一围绕资源归属字段：

- `users.managed_scope_id`
- `groups.managed_scope_id`
- `roles.namespace_scope_id`

当前实现要求：

- repo / orm 不再使用 `scope_type / scope_code` 做高频等值过滤
- 层级可见性统一落到 `VisibleScopeIDs` 或 `scope_visibility_map`
- 业务层不再手写 tenant/scope 判断作为主查询边界

## 6. 写模型

当前实现要求所有正式写路径都通过显式 `WriteConstraint`：

1. service 先调用 `Authorize(...)`
2. 从 allow 决策投影出 `WriteConstraint`
3. repo 在最终写边界校验：
   - 资源 ID
   - `managed_scope_id`
   - `revision/version`

这保证：

- 不会出现“前置校验通过，但最终落库越界”
- 不能通过隐式 context 猜测写边界
- `RowsAffected = 0` 不会被误判为成功

## 7. 菜单与特殊资源语义

### 7.1 Tenant

tenant 是业务配置资源，不再承担 platform 模拟职责。

### 7.2 Menu

菜单定义本身更接近平台级配置资源：

- 数据本体不再建模为 tenant-owned 资源
- 是否可见取决于当前 active scope、权限码与菜单自身 audience 规则

### 7.3 Self-owned

某些资源仍允许同时具备：

- 基于 `managed_scope_id` 的管理员可见性
- 基于 `owner_id` 的本人可见性

## 8. 迁移要求

从旧模型升级到当前模型时，必须一次性完成以下硬切：

1. 创建正式 scope 树与 `scope_visibility_map`
2. 为每个 tenant 创建 tenant root scope，并回填 `tenants.root_scope_id`
3. 删除 `is_platform` / `platform_slot`
4. 为用户、组织、角色等资源补齐正式归属字段
5. 创建 `user_role_bindings`，并回填 `grant_scope_id`
6. 删除 repo 内所有基于 `scope_type / scope_code` 的过滤实现
7. 删除基于 tenant 推断 active scope 的登录逻辑

不保留兼容层，不允许双语义共存。

## 9. 验收标准

当前实现要满足以下标准：

- 平台管理员可见所有下级 scope 的资源
- tenant 管理员只见本 tenant root scope 下资源
- self-owned 资源既支持 owner 访问，也支持管理者访问
- 标准 CRUD 不再手写 tenant/scope 判断
- 任何正式写操作都必须通过显式 `WriteConstraint`
- 不再出现“平台管理员看不到租户资源”或“租户管理员看不到自己”的模型级错误

## 10. 当前实现落点

实现主线分布在以下目录：

- `entity/*`
  - scope / tenant / user / role / user_role_binding / scope_visibility
- `repo/scope/*`
  - scope 树与 visibility 查询
- `service/scope_authorizer.go`
  - active scope、scope coverage、visible scope 解析
- `service/user/user.go`
  - 两阶段登录与 active scope 会话构造
- `middleware/auth.go`
  - 最小 token / activation token
- `middleware/auth_context.go`
  - access token -> Principal/DataScope 运行时恢复
- `router/auth.go`
  - `/auth/login`、`/auth/activate-scope`、`/auth/refresh`

## 11. 与上层设计文档的关系

- 规范级设计：`/home/alex/data/priv/project/gochen/docs/architecture/layered-authz-framework.md`
- 本文档：`gochen-iam` 当前实现态说明

如果两者出现冲突，应以规范级设计为准，并同步修正文档与实现，避免再次引入兼容层。
