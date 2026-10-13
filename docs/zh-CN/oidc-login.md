# OIDC 单点登录（实验性功能）

此功能默认关闭。它不需要数据库迁移，也不执行用户组同步。

## 配置

在 config.yaml 的 auth 下配置：

```yaml
auth:
  session_duration_hours: 12
  oidc:
    enabled: true
    issuer: https://sso.example.com
    client_id: cyberstrike
    client_secret: "从环境注入的密钥"
    redirect_uri: https://cyberstrike.example.com/api/auth/oidc/callback
    username_claim: preferred_username
    display_name_claim: name
```

OIDC Provider 注册 Web 客户端，使用 Authorization Code Flow 和 PKCE (S256)。应用要求 HTTPS Issuer、Discovery、Token、JWKS，当前只支持 RS256 签名的 ID Token。配置 Redirect URI 必须与反向代理实际对外地址一致。所有生产部署使用 HTTPS。

首次 SSO 登录会按配置 Claim 创建本地用户，默认 viewer；现有 OIDC 用户按用户名及 issuer+sub 指纹校验登录。未启用 OIDC 的本地密码账号、内置 admin 均不会因同名而被自动关联。OIDC 新建用户的 password_hash 字段保存 !oidc: 开头的身份指纹，不能通过本地密码登录。不可随意修改 Username Claim 的值，也不能将 OIDC 账号密码重置为本地密码，否则会破坏绑定。因为无数据库身份映射表，单个用户只支持一个 OIDC 身份，且用户名在 IdP 中必须稳定、唯一、不允许回收给其他用户。

服务端通过已有 Session Token 和 RBAC 完成授权。浏览器回调收到安全 Cookie；前端从 /api/auth/validate 恢复原有的 Session。OIDC 退出并不自动执行 IdP 全局登出。**生产启用前务必在隔离环境开展登录、注销、重启、用户禁用、同名账号冲突、代理 HTTPS、WebSocket/SSE 和 MFA 回归验证。**
