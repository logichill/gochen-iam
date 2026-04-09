# 域授权设计（完整 Scope 模型）

## 1. 设计目标

本方案的目标是：

1. 建立一套**完整的 Scope 授权模型**，统一表达平台、租户、组织、项目等授权域。
2. 让“谁可以管理谁”来自 **permission + scope 覆盖关系**，而不是来自角色名硬编码。
3. 兼容当前 `gochen-iam` 的现有数据模型与 API 习惯，优先渐进演进，而不是推倒重来。
4. 同时支持：
   - tenant-enabled 模式
   - tenant-disabled 模式
5. 保持 `roles` 作为业务概念继续存在，不要求把外部接口改叫 `role definition`。

> 当前代码阶段（2026-04-09）已先落地 **stage-1 materialized path**：
> `Scope.Path` 负责覆盖判定，`ScopeClosure` 暂不进入实现；文中的 closure 章节作为后续可选优化保留。

## 2. 非目标

本设计不追求下面这些事情：

1. 不做一套超泛化、一步到位覆盖所有 ABAC/OPA 场景的权限平台。
2. 不要求第一阶段就把所有实体都改成 `scope_id NOT NULL`。
3. 不要求第一阶段就删除现有 `tenant_id`、`user_roles`、`group_roles`。
4. 不要求公开 API 立刻从“角色管理”改名为“角色定义管理”。

也就是说，这是一套**完整目标模型 + 渐进落地方案**，不是只给出“理想国结构”而不考虑当前代码。

## 3. 适用范围

本设计用于当前 `gochen-iam` 的后续开发，默认基于现有事实展开：

- `users / roles / groups` 已携带 `tenant_id`
- 基础 CRUD 已有 tenant-aware 过滤
- JWT 与 request context 已有 `tenant_id`
- 当前 RBAC 能力已可满足租户内授权，但还缺统一的跨域授权骨架

因此，本文档的定位不是“重写全部 IAM 概念”，而是：

- 在现有 `gochen-iam` 上补出统一的授权域模型
- 给出结构体设计、运行规则与落地顺序
- 让后续开发可以直接按文档实现

## 4. 核心概念

完整 scope 模型中，建议先明确下面几个概念，再看结构体定义。

### 4.1 Scope

`Scope` 是授权域节点，是整个模型的核心。

它不是 tenant、group、project 的别名，而是一个更通用的概念：

- 平台是一个 scope
- 某个租户是一个 scope
- 某个组织单元也可以是一个 scope
- 某个项目、门店、工作区也可以是一个 scope

一个 scope 解决的是：

> 权限在什么边界内生效？资源归属到哪个授权域？谁能覆盖谁？

### 4.2 Subject

`Subject` 是被授予权限的主体。

在当前 `gochen-iam` 中，主体至少包括：

- `user`
- `group`

后续如有需要，还可以扩展：

- `service_account`
- `api_client`
- `bot`

### 4.3 Role

`Role` 仍然保留为业务概念。

也就是说：

- 用户仍然看到“角色”
- 管理接口仍然可以继续叫 `/roles`
- 现有 `entity/role.go` 的概念不需要在对外语义上被推翻

但在完整模型里，角色需要被更准确地理解为：

> 一组 permission 的命名集合，本身不直接回答“这个权限在哪个域中生效”，域范围要由 scope binding 来补全。

### 4.4 Permission

`Permission` 继续使用当前三段式权限码：

- `api:user:read`
- `api:user:write`
- `api:tenant:activate`
- `menu:user:view`

权限本身表达的是“可执行的动作”，但不表达它对哪个域生效。

### 4.5 Binding

`Binding` 表示：

> 某个 subject，在某个 scope 中，被授予了某个 role。

scope 模型真正解决的就是这三件事：

- 谁拿到了角色
- 角色在哪个域中生效
- 这个域能不能覆盖目标资源

### 4.6 Resource Ownership

被保护的资源最终都需要有“归属 scope”的概念。

在当前 `gochen-iam` 的过渡阶段，可以先通过：

- `tenant_id`
- `tenant.root_scope_id`

推导资源所属 scope；后续再逐步补实体级 `scope_id`。

### 4.7 概念之间的关系

后续实现时，可以直接按下面这组关系理解整套模型：

1. `tenant` 是业务对象，`scope` 是授权域对象  
   - 一个 tenant 对应一个 root scope  
   - `tenant.root_scope_id -> scope.id`

2. `role` 定义在某个 scope 中  
   - `role.NamespaceScopeID -> scope.id`

3. `subject` 通过 binding 拿到 role  
   - `binding.Subject -> user/group`
   - `binding.RoleID -> role.id`
   - `binding.ScopeID -> role 在哪个 scope 中生效`

4. `resource` 归属于某个 scope  
   - 当前阶段可先由 `tenant.root_scope_id` 推导
   - 后续逐步演进到显式 `resource.scope_id`

5. `permission` 由 `PermissionSpec` 声明  
   - 决定这个 permission 可以出现在哪类 scope 中
   - 不负责决定某个用户当前是否真的能操作某个资源

6. `ScopeAuthorizer` 负责最终裁决  
   - 取 actor 的有效 bindings
   - 找出包含目标 permission 的 bindings
   - 判断 `binding.ScopeID` 是否覆盖 `targetScopeID`

可以把这套关系压缩成一句话：

> role 定义 permission，binding 决定谁在什么 scope 中拥有 role，resource 决定目标在哪个 scope 中，authorizer 最终判断 binding scope 是否覆盖 target scope。

## 5. 权限定义

### 5.1 为什么不能继续依赖裸字符串权限码

当前 `gochen-iam` 已经有基于字符串权限码的 registry 机制，例如：

- `PermissionMiddleware("api:role:read")`
- `RegisterRequiredPermissionDefinitions(...)`

这套机制在“权限存在性校验”层面已经足够好用，但如果 scope 授权继续沿用“到处写字符串、再在别处补治理元数据”的方式，后续会出现一类非常常见的工程问题：

1. 同一个权限码在不同地方被手写多次，容易拼错。
2. `code` 与 `name / description / scope 治理规则` 分散在不同位置，容易不一致。
3. 当 `resource/action` 重命名时，代码扫描点、角色配置点、治理元数据点可能只改了一部分。
4. 注册中心虽然能校验“这个 code 是否存在”，但不能天然保证“这个 code 的治理属性和使用点是一致的”。

因此，完整 scope 模型下，权限不应再被建模为“若干零散字符串 + 一份松散 registry 元数据”，而应该提升为一个**中心化、强约束、可复用的声明对象**。

### 5.2 PermissionSpec：权限定义的单一事实源

推荐引入 `PermissionSpec` 作为权限声明模型。

```go
type Resource string
type Action string
type ScopeType string

const (
    ResourceRole   Resource = "role"
    ResourceUser   Resource = "user"
    ResourceTenant Resource = "tenant"
)

const (
    ActionRead  Action = "read"
    ActionWrite Action = "write"
    ActionList  Action = "list"
)

const (
    ScopePlatform ScopeType = "platform"
    ScopeTenant   ScopeType = "tenant"
)

type PermissionSpec struct {
    Code        string
    Type        PermissionType
    Resource    Resource
    Action      Action
    Name        string
    Description string

    Scopes    []ScopeType
    RiskLevel string
    BuiltinOnly bool
}
```

这里的关键点是：

- `Code` 不再被鼓励手写散落在各处
- `PermissionSpec` 本身就是权限定义、治理元数据和注册来源的统一载体
- 路由、中间件、角色配置、权限目录、后续审计都应该复用同一份 spec
- 在当前阶段，`permission` 只保留一个 `Scopes` 语义：
  - 表示该权限允许在哪些作用域中被授予并生效
- `target` 与 `namespace` 不再放在 `api permission` 上：
  - `target` 不是第一阶段必需元数据
  - `namespace` 更适合定义在 `role` 上，而不是定义在 `permission` 上

也就是说，系统中的单一事实源不再是：

- 某个字符串常量

而是：

- 一个完整的 `PermissionSpec`

### 5.3 在使用点定义权限，而不是退回到集中字符串表

当前项目的自然使用习惯是：

- 在 `PermissionMiddleware(...)` 的调用点声明权限
- 路由装配时自动把权限注册到 registry

这套使用方式本身是合理的，后续不需要把它强行改成“所有权限先集中定义成 `PermXxx` 常量再引用”。

推荐的主方案是：

- 继续在 `PermissionMiddleware(...)` 使用时定义权限
- 但不再传裸字符串，而是传 `ApiPermission(...)` 构造出的 `PermissionSpec`

也就是说，后续更推荐：

```go
PermissionMiddleware(
    ApiPermission(ResourceRole, ActionRead).
        Desc("读取角色").
        Scope(ScopePlatform, ScopeTenant),
)
```

而不是：

```go
PermissionMiddleware("api:role:read")
```

这样做的好处是：

1. 权限语义仍然留在使用点，读路由代码时最直观。
2. 不再依赖裸字符串，减少拼写错误。
3. 权限 code、描述和 scope 约束在同一处声明，不会分裂到多个文件。

### 5.4 不要用长位置参数，使用定义函数 + Option / Fluent Builder

虽然“定义权限时就把元数据一起传入”这个方向是对的，但不建议把 API 设计成一长串位置参数，例如：

```go
RegisterPermission("api:role:read", "api", "role", "read", "读取角色", "...", true, ...)
```

这种写法会带来新的问题：

- 参数过多后可读性很差
- 容易错位
- 演进时不兼容

更稳妥的方式是：

- 由 `resource + action` 自动生成 `Code`
- 用 `Option` 模式补充治理元数据
- 调用点风格尽量贴近业务语义，而不是暴露一大堆结构体字段

例如：

```go
type PermissionOption func(*PermissionSpec)

func ApiPermission(resource Resource, action Action, opts ...PermissionOption) PermissionSpec {
    spec := PermissionSpec{
        Code:     "api:" + string(resource) + ":" + string(action),
        Type:     PermissionTypeAPI,
        Resource: resource,
        Action:   action,
    }
    for _, opt := range opts {
        opt(&spec)
    }
    return spec
}
```

这样在使用点的权限声明会变成：

```go
PermissionMiddleware(
    ApiPermission(ResourceRole, ActionRead).
        Desc("读取角色").
        Scope(ScopePlatform, ScopeTenant),
)

PermissionMiddleware(
    ApiPermission(ResourceTenant, ActionWrite).
        Desc("创建租户").
        Scope(ScopePlatform).
        BuiltinOnly().
        Risk("critical"),
)
```

这比“裸字符串 + 分散元数据”更安全，也比“超长参数列表”更稳。

这里推荐的设计风格是：

- `Resource` 与 `Action` 都使用常量，避免继续手写字符串
- `Scope(...)` 是当前阶段唯一需要暴露在 permission 上的作用域语义
- 其余元数据都应有合理默认值

因此，更符合当前项目阶段的调用风格是：

```go
PermissionMiddleware(
    ApiPermission(ResourceRole, ActionRead).
        Desc("读取角色").
        Scope(ScopePlatform, ScopeTenant),
)
```

或者若支持轻量位置参数，也可以接受：

```go
PermissionMiddleware(
    ApiPermission(ResourceRole, ActionRead, Desc("读取角色"), Scope(ScopePlatform, ScopeTenant)),
)
```

但无论采用 fluent builder 还是 option 形式，都应坚持一条原则：

- 不鼓励再次退回到裸字符串 `PermissionMiddleware("api:role:read")`

更符合当前项目阶段的目标 API 是：

```go
PermissionMiddleware(
    ApiPermission(ResourceRole, ActionRead).
        Desc("读取角色").
        Scope(ScopePlatform, ScopeTenant),
)
```

如果实现时更喜欢 option 形式，也可以接受：

```go
PermissionMiddleware(
    ApiPermission(ResourceRole, ActionRead, Desc("读取角色"), Scope(ScopePlatform, ScopeTenant)),
)
```

但这两种形式应满足同一组约束：

- `Resource` 与 `Action` 使用常量，不再鼓励手写字符串
- `Scope(...)` 是当前阶段 permission 上唯一需要暴露的作用域语义
- 未显式填写的其余字段使用安全默认值
- 主使用方式仍然是“在 middleware 使用点定义”

只有当某个 permission 在同一模块中被重复引用很多次时，才允许局部提成变量；这只是可选复用手段，不应成为主设计。

### 5.5 Registry 冲突校验：保证同一个 code 的多次声明一致

既然权限在使用点定义，就必须正面解决一个问题：

> 同一个 permission code 如果在多个地方被重复声明，如何避免元数据不一致？

推荐规则是：

1. registry 继续以 `permission code` 为主键
2. 同一个 `code` 可以被重复注册
3. 如果重复注册时 `PermissionSpec` 归一化后完全一致，则允许
4. 如果同一个 `code` 的 `Resource/Action/Description/Scopes/BuiltinOnly/RiskLevel` 不一致，则启动期 fail-close

这意味着后续的 registry 不只是做“权限存在性登记”，还要承担“权限定义一致性校验”。

推荐的归一化后比对字段包括：

- `Code`
- `Type`
- `Resource`
- `Action`
- `Description`
- `Scopes`
- `BuiltinOnly`
- `RiskLevel`

这样就不需要把所有 permission 强制收进一个全局 `PermXxx` 文件，也能避免同名权限在不同路由里长成不同语义。

### 5.6 PermissionSpec 与当前 registry 的关系

当前项目的 required permissions registry 仍然有价值，不需要废弃。

推荐的职责划分是：

1. `PermissionSpec`
   - 权限定义的单一事实源
   - 负责表达：
     - code
     - type/resource/action
     - 展示信息
     - permission 级别的作用域规则（`Scopes`）

2. required permissions registry
   - 权限注册与严格模式校验机制
   - 负责回答：
     - 这个权限是否在系统中声明过
     - 哪些路由或模块依赖了它

3. scope 授权数据
   - 落库存储 scope、binding、resource ownership
   - 负责回答：
     - 这个权限由谁在什么域里拥有
     - 这次请求对目标 scope 是否生效

因此，不建议把“权限定义存在性”完全改造成数据库驱动，也不建议保留“字符串是事实源、元数据只是补丁”的状态。

更合理的是：

- `PermissionSpec` 是定义事实源
- registry 是运行期注册/校验投影
- 数据库保存 scope 授权关系

### 5.7 路由与业务代码如何使用 PermissionSpec

一旦引入 `PermissionSpec`，后续主流写法应当是：

```go
PermissionMiddleware(
    ApiPermission(ResourceRole, ActionRead).
        Desc("读取角色").
        Scope(ScopePlatform, ScopeTenant),
)
```

而不应再直接手写：

```go
PermissionMiddleware("api:role:read")
```

若 middleware 实现需要兼容当前风格，推荐只保留强类型入口：

```go
PermissionMiddleware(spec PermissionSpec)
```

由 middleware 内部完成：

```go
1. 规范化 `PermissionSpec`
2. 注册到 required permissions registry
3. 复用现有 permission checker 执行运行期校验
```

同样，角色配置页、角色写入校验、权限目录导出，也都应从 registry 中回读规范化后的 `PermissionSpec` 集合。

这样可以保证：

1. `code` 只定义一次
2. `resource/action` 与 `code` 自动一致
3. scope 治理元数据不会和 code 脱节
4. 重命名时修改面集中

### 5.8 这套设计如何解决租户自定义角色的越权问题

在完整 scope 模型中，租户自定义角色时并不是“任意勾选字符串权限”，而是从 `PermissionSpec` 目录里选择当前 scope 可分配的权限。

例如：

- 若 `ApiPermission(ResourceRole, ActionRead).Scope(ScopePlatform, ScopeTenant)` 对应的 `PermissionSpec.Scopes` 包含 `tenant`
  - 则租户可以把它放进自己的角色
- 若 `ApiPermission(ResourceTenant, ActionWrite).Scope(ScopePlatform)` 对应的 `PermissionSpec.Scopes` 仅包含 `platform`
  - 则租户侧角色配置时必须被拒绝

也就是说：

1. `PermissionSpec.Scopes` 先控制“这个权限能不能被这个 scope 的角色拥有”
2. `binding scope -> target scope coverage` 再控制“拥有以后能不能对当前目标生效”

两层叠加，才能既开放租户自助角色配置，又不把权限泄漏到 platform。

## 6. 完整数据模型

下面给出推荐的完整模型。

## 6.1 Scope 节点表

建议新增一张通用 scope 表，例如：

```go
type Scope struct {
    ID          int64
    Key         string
    Name        string
    Type        string
    ParentID    *int64
    Path        string
    Depth       int
    TenantID    *string
    Status      string
    Description string
}
```

推荐字段语义如下：

- `ID`
  - scope 主键
- `Key`
  - 在同一父 scope 或全局范围内可读的稳定标识
- `Name`
  - 展示名称
- `Type`
  - scope 类型，例如：
    - `platform`
    - `tenant`
    - `group`
    - `project`
    - `workspace`
- `ParentID`
  - 父 scope
- `Path`
  - 祖先路径，便于快速判断覆盖关系
- `Depth`
  - 层级深度
- `TenantID`
  - 可选，用于与现有 tenant 模型建立映射
- `Status`
  - active / inactive / archived
- `Description`
  - 说明

这里最重要的点是：

- `platform` 是一条正式的 `scope.type = platform` 记录
- 它不是魔法字符串判断
- tenant 只是某种 scope type，而不是整个授权模型本身

## 6.2 Scope 关系表

如果系统后续要频繁做祖先/后代判断，建议除了 `ParentID`，再配一张 closure table：

```go
type ScopeClosure struct {
    AncestorID   int64
    DescendantID int64
    Distance     int
}
```

这张表的作用是：

- 快速判断某个 scope 是否覆盖另一个 scope
- 支持高效的祖先/后代查询
- 避免每次授权都递归查父链

推荐规则：

- 自反关系也要保留
- 即 `scope-a -> scope-a` 的 `distance = 0`

这样“同域访问”与“祖先覆盖后代访问”可以统一处理。

### 6.2.1 ScopeClosure 的维护成本与适用边界

closure table 的优势是读快，但维护成本不能省略。

推荐在设计上明确以下策略：

1. scope 创建时
   - 插入一条自反记录：`self -> self`
   - 为所有祖先 scope 补齐到新节点的 closure 记录

2. scope 删除时
   - 删除该节点与其子树相关的 closure 记录
   - 若采用软删，closure 也应同步做失效处理，避免覆盖关系误判

3. scope 移动时
   - 需要重建整棵子树的 closure 关系
   - 这是 closure table 最昂贵的操作

因此，closure table 更适合：

- scope 树读多写少
- 层级关系稳定
- 祖先/后代判断频繁

这与大多数 SaaS 平台的租户/平台授权域非常契合，因为：

- tenant / platform / region 这类授权域变更频率通常远低于读操作

如果未来 scope 树变更非常频繁，可评估替代方案：

1. 只保留 `Path`，运行期通过前缀/LIKE 做覆盖判断
2. 使用物化路径并由数据库触发器维护

但在当前阶段，closure table 仍然是更稳妥的主推荐方案。

## 6.3 Tenant 与 Scope 的映射

当前项目已经有 `entity/tenant.go`，因此不建议删除 tenant。

推荐做法是：

- `tenant` 继续保留为业务租户对象
- 每个 tenant 对应一个 root scope
- 在 tenant 表中增加 `RootScopeID`

例如：

```go
type Tenant struct {
    ...
    RootScopeID *int64
}
```

这样 tenant 与 scope 的职责就分清了：

- `tenant`
  - 业务租户对象
  - 负责租户生命周期、展示信息、业务配置
- `scope`
  - 授权域对象
  - 负责访问范围与层级关系

这能避免把“租户”和“授权域”混成同一个概念。

## 6.4 Role 表

为了兼容当前模型，`roles` 仍然保留。

推荐在完整设计里，把 role 理解为“权限集合定义”，同时给它加一个所属管理域：

```go
type Role struct {
    ID               int64
    Code             string
    Name             string
    Description      string
    NamespaceScopeID int64
    Permissions      []string
    IsSystem         bool
    Status           string
}
```

字段含义：

- `NamespaceScopeID`
  - 这个角色是在哪个 scope 中定义、管理和维护的

这不是说 role 只能在这个 scope 中生效，而是说：

- 角色定义归谁管理
- 谁可以修改这个角色
- 这个角色默认属于哪个域的角色目录

这里要特别强调：

- `namespace` 是 `role` 的属性，不是 `permission` 的属性
- 当前阶段不建议在 `ApiPermission(...)` 上再额外声明 `NamespaceIn(...)`
- “哪个角色目录可以包含哪些 permission”应由：
  - `role.NamespaceScopeID`
  - `permission.Scopes`
  - 角色写入校验
    共同决定

### 6.4.1 角色创建/更新时的权限校验

完整 scope 模型落地后，角色写入不应只做“权限 code 是否存在”的校验，还要校验：

- 角色定义所在的 namespace scope
- permission 是否允许出现在该 scope 类型下

推荐 service 层显式提供类似能力：

```go
func (s *RoleService) ValidatePermissionsForScope(
    ctx context.Context,
    permissions []string,
    namespaceScopeID int64,
) error
```

核心流程：

1. 加载 `namespaceScopeID` 对应的 scope
2. 读取每个 permission 对应的 `PermissionSpec`
3. 校验：
   - spec 是否存在
   - `scope.Type` 是否命中 `spec.Scopes`
   - 若 `BuiltinOnly=true`，当前角色是否属于平台内置角色目录
4. 任一失败则拒绝角色创建/更新

这样可以直接拦住下面这类越权写入：

- 租户管理员尝试创建包含 `api:tenant:create` 的角色
- tenant scope 下的普通角色尝试持有 platform-only 权限

例如：

- `system_admin` 定义在 `platform` scope
- `tenant_admin` 定义在某个 tenant root scope
- 某个项目管理员角色定义在 project scope

### 为什么这里还保留 `roles`

这是为了兼容当前项目和你的要求：

- 外部概念仍然叫 `roles`
- 不强迫把系统公开地改成 `role define`
- 但内部设计上，我们明确 role 只是“权限集合”，不直接表达授予范围

## 6.5 Subject Role Binding 表

完整 scope 模型里，推荐新增一张统一的 binding 表：

```go
type SubjectRoleBinding struct {
    ID          int64
    SubjectType string
    SubjectID   int64
    RoleID      int64
    ScopeID     int64
    Effect      string
    ExpiresAt   *time.Time
}
```

字段说明：

- `SubjectType`
  - `user` / `group` / `service_account`
- `SubjectID`
  - 主体 ID
- `RoleID`
  - 被授予的角色
- `ScopeID`
  - 这次角色授予在哪个 scope 中生效
- `Effect`
  - 预留 allow / deny / delegated 等语义
- `ExpiresAt`
  - 预留临时授权能力

这张表是完整设计的关键。

因为它能自然表达：

1. `u1` 在 `platform` scope 中被授予 `system_admin`
2. `u2` 在 `tenant-a` scope 中被授予 `admin`
3. `group-ops` 在 `region-a` scope 中被授予 `operator`

而且未来如果要支持：

- 临时授权
- 委派授权
- 到期失效

也不需要推翻结构。

## 6.6 当前 `user_roles / group_roles` 与统一 Binding 的关系

当前项目已有：

- `user_roles`
- `group_roles`

在完整设计中，可以把它们视作统一 binding 的特化版本：

- `user_roles`
  - 等价于 `SubjectType=user`
- `group_roles`
  - 等价于 `SubjectType=group`

渐进落地时有两条路：

1. 第一阶段保留 `user_roles / group_roles`，并补一个 `scope_id`
2. 后续再统一迁移到 `subject_role_bindings`

推荐路径是第一条，因为更平滑。

## 6.7 资源的 Scope Ownership

被权限保护的业务资源，最终都应该能回答：

> 这个资源归属于哪个 scope？

推荐目标状态：

- `users.scope_id`
- `groups.scope_id`
- `roles.namespace_scope_id`
- `menus.scope_id`
- 未来其他业务资源也有自己的 `scope_id`

在当前阶段，为了兼容现有多租户结构，可以先采取过渡方案：

- `tenant_id` 仍然保留
- 通过 `tenant.root_scope_id` 把资源映射到 tenant scope
- 后续逐步引入实体级 `scope_id`

## 7. 平台、租户、组织在 Scope 模型中的位置

### 7.1 platform 如何定义

`platform` 不应该是魔法 tenant_id，也不应该只是约定字符串。

在完整模型里，它应当是：

- 一条正式的 scope 记录
- `scope.type = platform`
- 没有父节点
- 是整棵 scope 树的根

是否需要平台 tenant，可以这样处理：

1. 如果当前项目依然希望“system admin 也像普通用户一样归属某个 tenant”
   - 可以保留一个 `platform tenant`
   - 并将它的 `root_scope_id` 指向 platform scope
2. 如果未来想把平台层与 tenant 层彻底分开
   - 也可以让 platform 只有 scope，没有 tenant

对当前 `gochen-iam` 而言，推荐第一种：

- 继续保留 platform tenant，兼容当前用户、JWT、请求上下文中的 tenant 语义
- 但授权时依赖的是 platform scope，而不是 platform tenant 字面值
- 当前代码阶段建议用显式字段（如 `tenants.is_platform=true`）标记“这个 tenant 直接映射到 platform scope”
  - 这样 platform tenant 是业务配置，不是魔法字符串
  - 该 tenant 的 `root_scope_id` 应回写为 platform scope
  - 该 tenant 下签发的 token `active_scope_type` 应为 `platform`
  - 持久化层还应增加唯一哨兵，确保全库只能存在一个 platform tenant

### 7.2 tenant 如何定义

tenant 在完整模型里不是被删除，而是被“纳入 scope 体系”：

- 每个 tenant 对应一个 root tenant scope
- scope.type = tenant
- parent = platform scope

这样 tenant 既有业务对象身份，也有授权域映射。

### 7.3 group 是否等于 scope

不建议默认把当前业务组织树 `group` 直接等同于授权 scope。

原因是：

1. 业务组织树和授权域树不一定一一对应
2. 组织结构经常为了展示、汇报、归档而变化
3. 授权域通常更偏“治理边界”，变化频率应更低

更稳妥的设计是：

- 当前阶段：`group` 仍然是业务组织对象，不直接成为 scope
- 如果未来确实需要“组织级授权域”
  - 可以让特定 group 映射到对应 scope
  - 而不是强制所有 group 都是 scope

## 8. 授权判定语义

完整 scope 模型下，授权不再是“有这个角色名就行”，而是一个统一公式：

```text
Allow =
  HasPermission(actor, action) &&
  HasActiveBinding(actor, role, bindingScope) &&
  ScopeCovers(bindingScope, targetScope)
```

可以更具体地写成：

1. 收集 actor 的所有有效 role bindings
2. 计算这些角色聚合出来的 permissions
3. 过滤出包含目标 permission 的 bindings
4. 对每个候选 binding，判断其 `binding.scope_id` 是否覆盖 `target.scope_id`
5. 任一 binding 满足则允许，否则拒绝

### 8.0 绑定合并与冲突策略

文档中的 `SubjectRoleBinding` 结构预留了 `Effect` 字段，但第一阶段不建议把模型做得过重。

推荐第一阶段规则明确为：

1. 只支持 `allow` binding
2. 忽略过期 binding、失效 role、失效 scope
3. actor 的有效权限集合为所有有效 binding 的权限并集
4. 访问某个 target scope 时，只保留能够覆盖该 target scope 的 binding
5. 如果有多条 binding 同时允许，则：
   - 授权结果为允许
   - 审计时记录“最小可覆盖 target 的 binding”

其中“最小可覆盖 target 的 binding”指：

- 在所有可放行的 binding 中，优先记录 scope 最接近 target 的那一条

这样做的好处是：

- 授权语义简单，易实现
- 不会一上来引入 deny 语义的复杂组合逻辑
- 审计解释更稳定

`deny` 可以保留为后续演进点，但不应在第一阶段文档中当作既定运行规则。

### 8.1 为什么 system admin 可以管理所有

因为它的授权不是来自角色名硬编码，而是来自下面这条事实：

1. `system_admin` 被授予给某个 user
2. 该 binding 的 `scope_id = platform_scope`
3. `platform_scope` 覆盖所有 tenant scopes
4. 该角色同时拥有目标操作所需 permission

因此允许。

### 8.2 为什么 tenant admin 只能管理自己

同理：

1. `tenant_admin` 被授予给某个 user
2. 该 binding 的 `scope_id = tenant_a_scope`
3. `tenant_a_scope` 只覆盖自己，或者覆盖自己下面的子 scopes
4. 它并不覆盖 `tenant_b_scope`

因此不能跨租户管理。

### 8.3 为什么这比角色名特判更稳

因为它把“为什么允许”明确建模为：

- permission
- binding
- scope coverage

### 8.4 JWT / Claims 与 active scope 语义

当前 `gochen-iam` 的 JWT claims 已携带 `tenant_id`。引入 scope 后，最容易出错的地方不是字段名，而是：

> token 究竟表达“用户所有授权关系”，还是表达“当前请求使用的 active scope”？

推荐第一阶段明确如下：

1. JWT 不承载“全部 bindings 列表”
   - 完整 binding 关系应由数据库或缓存中的 authorizer 负责

2. JWT 可以继续保留：
   - `user_id`
   - `tenant_id`（兼容当前 tenant-aware 逻辑）
   - `roles/permissions`（仅作为当前 active scope 的快照，或兼容快照）

3. 若系统进入 scoped mode，应新增：
   - `active_scope_id`
   - `active_scope_type`

4. token 中的 `tenant_id` 与 `active_scope_id` 的关系：
   - 在 tenant-enabled 模式下，若 active scope 对应某 tenant root scope，则 `tenant_id` 仍可保留
   - 在 tenant-disabled/simple mode 下，`tenant_id` 可以为空或省略，active scope 退化为系统默认 scope

5. 运行期真正的权限裁决不应只信 token 里的 `permissions`
   - token 快照用于快速鉴权与兼容
   - 最终 scope coverage 与 binding 生效判断应回到 authorizer

这意味着，scope 引入后 JWT 的推荐语义是：

- token 表示“当前 active scope 的身份快照”
- 不是“全量授权拓扑的离线缓存”

### 8.5 ScopeAuthorizer 的推荐职责与执行顺序

文档中的 `ScopeAuthorizer` 不应只是一个很薄的接口名词，而应该成为后续所有 service 的统一授权入口。

推荐接口形态至少包含：

```go
type ScopeAuthorizer interface {
    ScopeCovers(ctx context.Context, ancestorScopeID, descendantScopeID int64) (bool, error)
    GetActiveBindings(ctx context.Context, actorID int64) ([]*SubjectRoleBinding, error)
    GetEffectiveBindings(ctx context.Context, actorID, targetScopeID int64) ([]*SubjectRoleBinding, error)
    RequirePermissionInScope(ctx context.Context, permission PermissionSpec, targetScopeID int64) error
}
```

推荐执行顺序：

1. 从 request context 解析 actor 身份与 active scope
2. 加载 actor 的全部有效 bindings
3. 过滤出包含目标 permission 的 bindings
4. 对每条候选 binding 执行 `ScopeCovers(binding.ScopeID, targetScopeID)`
5. 选出能够覆盖 target 的最小 binding 作为审计来源
6. 命中则放行，否则返回 forbidden

推荐伪代码：

```go
func (a *authorizer) RequirePermissionInScope(
    ctx context.Context,
    perm PermissionSpec,
    targetScopeID int64,
) error {
    actor := MustActorFromContext(ctx)
    bindings, err := a.GetActiveBindings(ctx, actor.UserID)
    if err != nil {
        return err
    }

    candidates := make([]*SubjectRoleBinding, 0, len(bindings))
    for _, binding := range bindings {
        role, err := a.roleRepo.Get(ctx, binding.RoleID)
        if err != nil {
            return err
        }
        if role != nil && role.HasPermission(perm.Code) {
            candidates = append(candidates, binding)
        }
    }

    effective := make([]*SubjectRoleBinding, 0, len(candidates))
    for _, binding := range candidates {
        covers, err := a.ScopeCovers(ctx, binding.ScopeID, targetScopeID)
        if err != nil {
            return err
        }
        if covers {
            effective = append(effective, binding)
        }
    }

    if len(effective) == 0 {
        return errorx.New(errorx.Forbidden, "permission denied in target scope")
    }

    return nil
}
```

注意：

- `PermissionMiddleware(...)` 仍可用于快速注册和基础权限门禁
- 但真正涉及 target scope 的 service 操作，应统一走 `ScopeAuthorizer`

而不是：

- 某个角色名看起来比较大

## 9. 典型授权示例

### 9.1 平台管理员

结构：

```text
platform
├── tenant-a
└── tenant-b
```

授权：

- `user:u1`
- binding: `u1 -> system_admin @ platform`

结果：

- 可管理 `tenant-a`
- 可管理 `tenant-b`

### 9.2 租户管理员

授权：

- `user:u2`
- binding: `u2 -> admin @ tenant-a`

结果：

- 可管理 `tenant-a` 下资源
- 不可管理 `tenant-b`

### 9.3 区域管理员

结构：

```text
platform
└── region-a
    ├── store-a1
    └── store-a2
```

授权：

- `user:u3`
- binding: `u3 -> operator @ region-a`

结果：

- 可管理 `store-a1`
- 可管理 `store-a2`
- 不可管理 `tenant-b` 或 `region-b`

这就是完整 scope 模型的价值：它不是专门为 tenant 写的，而是能统一处理所有层级域。

## 10. 与当前 `gochen-iam` 的映射

完整模型不等于当前代码必须重写。

关键是要把它与现有项目对齐。

### 10.1 当前 `tenant_id` 如何映射

当前：

- `users.tenant_id`
- `roles.tenant_id`
- `groups.tenant_id`

完整设计中的过渡映射建议是：

- `tenant_id` 暂时继续保留，作为业务分区字段
- 每个 tenant 有一个 `root_scope_id`
- 当前所有基于 `tenant_id` 的资源，先默认归属于 `tenant.root_scope_id`

这样现有 CRUD、JWT、请求上下文不会立刻失效。

### 10.2 当前 `roles` 如何映射

当前 `entity/role.go` 里：

- 角色已经是 permission bundle
- 角色带 `tenant_id`
- 用户/组织通过多对多关联拿到角色

在完整设计里，可以这样映射：

- 当前 `roles.tenant_id`
  - 先映射为 `role.namespace_scope_id`
- 当前 `user_roles` / `group_roles`
  - 先视作 scope binding 的特化实现
- 第一阶段如果还没有显式 `binding.scope_id`
  - 默认它等于 role 所在 tenant 对应的 root scope

这意味着：

- 现有 `roles` 不需要对外改名
- 但内部语义会从“租户内角色”升级为“可在 scope 中定义并授予的角色”

### 10.3 当前 `AdminOnlyMiddleware()` 如何映射

当前：

```go
AdminOnlyMiddleware() == RoleMiddleware("system_admin")
```

在完整设计里，这种做法应该逐步废弃。

推荐目标是：

- middleware 只做认证和基础 permission gating
- 真正的 scope 覆盖判断收口到统一 authorizer

也就是说，将来更合理的是：

- `PermissionMiddleware("api:tenant:write")`
- 再由 service/authorizer 判断：
  - actor 是否在某个 binding scope 中拥有该 permission
  - 该 binding scope 是否覆盖 target scope

### 10.4 当前 `RequireSameTenant / RequireSameTenantOrAdmin`

它们可以继续保留一段时间，但推荐作为过渡 helper。

最终目标应当是：

- `RequireScopeAccess(...)`
- `RequireResourceAccess(...)`
- `RequireBindingScopeCoverage(...)`

让“同 tenant”变成完整 scope 判定中的一个特例，而不是主模型本身。

## 11. Tenant-enabled 与 Tenant-disabled

完整 scope 模型的一大优势，是能优雅覆盖这两种模式。

### 11.1 tenant-enabled

在 tenant-enabled 模式下：

- 每个 tenant 对应一个 root tenant scope
- 请求上下文中可继续保留 `tenant_id`
- 业务资源默认归属 tenant root scope

这与当前 `gochen-iam` 最贴近。

### 11.2 tenant-disabled

在 tenant-disabled 模式下：

- 不要求业务数据必须带 `tenant_id`
- 但授权体系仍然保留 scope
- 所有资源默认挂在某个全局 root scope 之下

最简单的实现是：

- 使用 `platform` 或 `global` 作为唯一根 scope
- 所有权限判断继续走 scope binding
- 只是没有 tenant 这一层业务对象

这意味着：

- tenant 可以不存在
- scope 不能不存在

因为 scope 是授权模型的基础骨架。

### 11.3 Simple Mode：面向单租户/固定租户的极简运行方式

完整 scope 模型是统一内核，但单租户系统不应该被迫理解全部概念。

因此文档推荐显式支持一种 simple mode，用于：

- 单租户系统
- fixed tenant 模式
- 不需要 platform/tenant 多层授权树的场景

simple mode 下的约定：

1. 系统只有一个默认 scope
   - 可以叫 `global`
   - 也可以直接映射到固定 tenant 的 root scope

2. 业务方无需显式维护 scope 树
   - 没有多层级 scope 时，也不需要维护 closure table

3. `ApiPermission(...).Scope(...)` 对调用方是可选的
   - 不传时，默认使用系统唯一 scope

4. binding 可以退化为：
   - “角色在默认 scope 中生效”

5. JWT 不要求承载复杂 scope 信息
   - 保留当前最小 claims 即可

也就是说，single-tenant 项目可以使用同一套授权内核，但接入面仍保持接近当前 RBAC 的体验。

### 11.4 Scoped Mode：面向多租户/平台治理的完整运行方式

只有在真正需要下面这些能力时，才进入 scoped mode：

- platform 管理所有 tenant
- tenant 管理自己
- 多 binding
- scope coverage
- active scope 切换

scoped mode 下才显式启用：

- `platform scope`
- `tenant root scopes`
- `subject_role_bindings`
- `scope_closure`
- `active_scope_id`

这样可以避免把完整模型的复杂度强塞给单租户系统。

## 12. 角色与 Scope 的推荐语义

为了兼容当前项目，同时表达完整 scope 模型，推荐如下约定。

### 12.1 `system_admin`

- 角色定义位于 `platform` scope
- 绑定生效在 `platform` scope
- 默认拥有平台治理权限，或者拥有 `*:*:*`

### 12.2 `admin`

- 可以是租户内 builtin role
- 定义位于 tenant scope
- 绑定生效在对应 tenant scope

### 12.3 `user`

- 普通基础角色
- 绑定在用户所属 scope 中

### 12.4 未来新增的角色

如果以后有：

- `tenant_operator`
- `region_admin`
- `project_owner`

都不需要再新增授权模型，只要新增 role + binding 即可。

## 13. 推荐的落地顺序

完整 scope 设计不应该一把切。

推荐按下面顺序推进。

### 阶段 1：建立 Scope 主模型

新增：

- `scopes`
- `scope_closure`

并在 `tenants` 中增加：

- `root_scope_id`

目标：

- 先把授权域对象正式建起来
- 让 `platform` 成为正式 scope，而不是魔法值

### 阶段 2：建立 Role Binding 能力

新增：

- `subject_role_bindings`

或先给当前：

- `user_roles`
- `group_roles`

补 `scope_id`

目标：

- 明确“角色授予在哪个 scope 中生效”

### 阶段 3：补统一 Authorizer

新增统一能力，例如：

```go
type ScopeAuthorizer interface {
    ScopeCovers(ctx context.Context, ancestorScopeID, descendantScopeID int64) (bool, error)
    GetActiveBindings(ctx context.Context, actorID int64) ([]*SubjectRoleBinding, error)
    GetEffectiveBindings(ctx context.Context, actorID, targetScopeID int64) ([]*SubjectRoleBinding, error)
    RequirePermissionInScope(ctx context.Context, permission PermissionSpec, targetScopeID int64) error
}
```

目标：

- 把权限判断从 middleware/router/service 各自为战，收口成统一入口

### 阶段 4：资源逐步引入 `scope_id`

先从这些实体开始：

- users
- roles
- groups

再逐步扩展到其他业务资源。

### 阶段 5：让 `tenant_id` 从授权主字段退居兼容字段

最终目标不是马上删除 `tenant_id`，而是：

- 让真正的授权判定以 `scope_id` 为准
- `tenant_id` 退化为：
  - 业务分区字段
  - 兼容查询字段
  - 迁移过渡字段

## 14. 为什么这套设计依然“基于现有结构扩展”

虽然这是完整 scope 模型，但它仍然尽量贴着当前 `gochen-iam`：

1. `roles` 继续保留，不要求外部 API 改名
2. `user_roles / group_roles` 可以先继续用，不要求立刻换表
3. `tenant_id` 可以保留相当长一段时间
4. `platform tenant` 也可以继续保留，兼容当前登录与请求上下文
5. 现有 `PermissionMiddleware`、JWT、CRUD wrapper 都还能复用

变化的核心只有一个：

> 把“租户内 RBAC”升级为“基于 scope 的分层授权”

这就是为什么它不是“阉割版本”，但也不是“大刀阔斧改掉一切”。

## 15. 需要明确的几个工程结论

### 15.1 `platform` 不是魔法标记

它必须是正式 scope 记录。

### 15.2 `system_admin` 不是天生超能力角色

它能管理所有，是因为：

- 它在 platform scope 中被授予角色
- 这个 binding scope 覆盖所有业务 scope

### 15.3 tenant 不是授权模型本身

tenant 是业务对象，scope 才是授权骨架。

### 15.4 role 不等于 binding

role 是 permission bundle，binding 才决定“谁在什么域中拥有它”。

### 15.5 PermissionSpec 应成为权限定义单一事实源

权限定义不应继续以裸字符串为中心，而应以中心化的 `PermissionSpec` 为中心：

- `Code` 应由 `resource/action` 自动生成
- `Scope(...)` 应成为当前阶段 permission 上唯一需要暴露的作用域语义
- 主使用方式应是在 `PermissionMiddleware(...)` 使用点声明 spec
- registry 需要对同 code 的重复声明做一致性校验
- middleware、角色配置、权限目录都应复用同一份 spec

### 15.6 单租户场景必须有 Simple Mode

完整 scope 是统一内核，但单租户系统不应被迫承担全部概念负担。

因此必须提供：

- 单默认 scope
- 可省略的 `Scope(...)`
- 无需显式 scope tree 的 simple mode

### 15.7 同租户只是 scope 判定的一个特例

未来系统真正要统一的是：

- 同域
- 祖先域
- 子域
- 平级域

这些关系。

## 16. 结论

面向 `gochen-iam` 的长期演进，真正稳的方案不是把 tenant 勉强扩成授权域，也不是继续靠 `system_admin` 角色名硬编码兜底，而是：

1. 建立正式的 `Scope` 模型
2. 让 tenant 与 scope 建立映射，而不是相互替代
3. 保留 `roles` 作为业务概念，但通过 binding 明确授予范围
4. 让授权判定统一基于：
   - permission
   - role binding
   - scope coverage

这套模型既能解释今天的 platform / tenant / admin / system_admin，也能支撑明天更复杂的层级域授权需求。
