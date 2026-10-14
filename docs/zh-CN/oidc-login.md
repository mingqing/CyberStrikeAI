# OIDC 单点登录（实验性功能）

此功能默认关闭。它不需要数据库迁移，也不执行用户组同步。

## 配置

在 config.yaml 的 auth 下配置：

```yaml
auth:
  session_duration_hours: 12
  oidc:
    enabled: true
    allow_http: false  # 在明确接受明文传输风险的隔离环境可设为 true
    issuer: https://sso.example.com
    # discovery_url: https://sso.example.com/api/oauth2/.well-known/openid-configuration
    client_id: cyberstrike
    client_secret: "从环境注入的密钥"
    redirect_uri: https://cyberstrike.example.com/api/auth/oidc/callback
    claims:
      username: preferred_username
      display_name: name
```

`discovery_url` 是可选配置。省略时自动请求 `<issuer>/.well-known/openid-configuration`；提供时直接请求该 URL，但仍要求发现文档的 `issuer` 与配置的 `issuer` 完全一致，并验证 ID Token 的 `iss`。自定义 URL 同样遵守 `allow_http` 的 HTTP/HTTPS 限制。示例：`issuer: http://192.168.0.1:8080` 与 `discovery_url: http://192.168.0.1:8080/api/oauth2/.well-known/openid-configuration`。若发现文档发布的 issuer 不同，应使用发现文档中的实际值，不能通过跳过校验兼容。\n\nOIDC Provider 注册 Web 客户端，使用 Authorization Code Flow 和 PKCE (S256)。默认要求 HTTPS Issuer、Discovery、Token、JWKS 和 Redirect URI；启用 `allow_http: true` 后也允许这些地址使用 HTTP。Cookie 的 Secure 属性按照配置的 Redirect URI Scheme 设置。当前只支持 RS256 签名的 ID Token。配置 Redirect URI 必须与对外访问地址一致。生产环境强烈推荐 HTTPS；HTTP 可能暴露授权码、客户端密钥及会话 Cookie，仅适合隔离开发环境。

首次 SSO 登录会按配置 Claim 创建本地用户，默认 viewer；现有 OIDC 用户按用户名及 issuer+sub 指纹校验登录。未启用 OIDC 的本地密码账号、内置 admin 均不会因同名而被自动关联。OIDC 新建用户的 password_hash 字段保存 !oidc: 开头的身份指纹，不能通过本地密码登录。不可随意修改 Username Claim 的值，也不能将 OIDC 账号密码重置为本地密码，否则会破坏绑定。因为无数据库身份映射表，单个用户只支持一个 OIDC 身份，且用户名在 IdP 中必须稳定、唯一、不允许回收给其他用户。

服务端通过已有 Session Token 和 RBAC 完成授权。浏览器回调收到安全 Cookie；前端从 /api/auth/validate 恢复原有的 Session。OIDC 退出并不自动执行 IdP 全局登出。**生产启用前务必在隔离环境开展登录、注销、重启、用户禁用、同名账号冲突、代理 HTTPS、WebSocket/SSE 和 MFA 回归验证。**


## 未来扩展：OIDC Groups 到 RBAC Roles（设计预留，尚未实现）

> **状态：仅设计，不属于当前 OIDC 登录功能。** 不要在当前配置中启用以下字段；当前 Go 代码不会解析或执行角色映射。本次扩展不修改数据库表结构、不同步 LDAP/SCIM 用户组。

### 拟议配置（不可直接用于当前版本）

```yaml
auth:
  oidc:
    # 当前已支持的 claims 配置保持不变
    claims:
      username: preferred_username
      display_name: name
      # groups: groups   # 未来支持：OIDC ID Token / UserInfo 的组属性

    # 未来可选配置；当前未实现
    # role_mapping:
    #   enabled: false
    #   default_role: viewer
    #   mappings:
    #     cyberstrike-operators: operator
    #     cyberstrike-auditors: auditor
    #     # 高权限 admin 映射需要额外显式授权
```

### 建议语义与实现边界

1. `claims.groups` 只负责指定上游 Claims 字段，`role_mapping.mappings` 负责将组名映射到本地 RBAC Role ID；与 `username` / `display_name` 的字段映射职责分离。
2. 仅对已验证的 ID Token 或完成 `sub` 一致性验证的 UserInfo 提取 Groups。第一版仅支持字符串数组和组名精确匹配；不实现 LDAP 查询、正则、嵌套组及目录同步。
3. 一个用户可以匹配多个组；映射后的角色去重。没有匹配时默认使用 `viewer`；Claims 缺失、格式错误及未知 Role 应明确记录审计并使用拒绝或最小权限策略，不能默默保留旧的高权限角色。
4. **不直接把 OIDC 派生角色写入 `rbac_user_roles`**，以免与管理员人工分配的角色混淆。推荐由 OIDC 登录流程构建本次会话的有效角色集合，再由统一 RBAC 解析器计算 `Session.Roles`、`Session.Permissions`、`Session.PermissionScopes` 和 `Session.Scope`。本地密码登录行为保持原样。
5. `admin`、C2、WebShell 等高风险权限的自动授予应默认拒绝，必须有显式策略、授权审查与审计；禁止把单纯的 OIDC 登录成功解释为全权限操作员。
6. 现有 Session 是内存权限快照，上游组变更无法实时撤销既有会话。未来上线角色映射时需明确有效期、主动撤销策略、配置变更后的会话失效、用户禁用以及权限更新一致性；不应宣称实时同步。
7. 仍需处理 RBAC 资源访问路径（例如 `UserCanAccessResource`）、Agent/MCP 使用的 Principal，以及本地角色/会话角色权限合并的一致性。上线前补充多组映射、组移除、未知组、同名用户冲突、管理员映射、登录态过期等测试。

### 未来实施范围

预估额外约 250–450 行 Go 代码及测试（粗略估算），主要涉及 OIDC Claims 提取、组映射与 RBAC 有效权限解析。**当前版本不新增以上配置字段、不修改 RBAC、不修改数据库、不改变现有默认 Viewer 行为。**
