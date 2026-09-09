# 网站应用接入指南（SSO）

面向内部团队网站：把本服务当作统一登录/授权入口。标准 **OAuth 2.1 授权码 + PKCE** 流程，
用户会看到明确的授权确认页（同意/拒绝）。文档假设你的回调域名为 `https://your-app.acme.com`。

## 1. 接入申请（提前注册）

网站应用**不支持自助注册**，接入前联系本服务团队登记以下信息：

| 需要你提供 | 我们返回 |
|------------|----------|
| 应用名称、回调地址（`redirect_uri`，精确匹配，必须 HTTPS）、所需 scope（权限标签，确认页会展示给用户；示例为 `profile`）| `client_id` + `client_secret` |

`client_secret` 只能保存在你的**网站后端**，绝不能出现在前端页面/移动端包里。

## 2. 登录流程（三步）

### ① 重定向用户浏览器到授权端点

```
https://www.research.acme.com/oauth2/authorize
    ?response_type=code
    &client_id=<你的 client_id>
    &redirect_uri=https://your-app.acme.com/auth/callback
    &scope=profile
    &state=<随机串，用于防 CSRF，回调时必须校验>
    &code_challenge=<BASE64URL(SHA256(code_verifier))>
    &code_challenge_method=S256
```

PKCE 必须：`code_verifier` 是 43~128 位随机字符串，`code_challenge` 是其 SHA-256 的
Base64URL 编码（每次登录生成新的）。

### ② 用户登录并确认授权 → 回调你的 redirect_uri

用户先完成平台登录（未登录会被引导到登录页），然后看到授权确认页，**同意**后浏览器被重定向回：

```
https://your-app.acme.com/auth/callback?code=<授权码>&state=<原样返回，先校验！>
```

用户**拒绝**时同样会回调，但带的是 `error=access_denied&state=...`——请按"用户取消登录"处理。

### ③ 你的后端用授权码换令牌（仅后端调用）

```
POST https://www.research.acme.com/oauth2/token
Authorization: Basic(base64(client_id:client_secret))
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=<①②中的授权码>
&redirect_uri=https://your-app.acme.com/auth/callback
&code_verifier=<①中的 code_verifier>
```

成功返回：

```json
{
  "access_token": "<JWT，代表该用户>",
  "refresh_token": "<用于续期>",
  "token_type": "Bearer",
  "expires_in": 300
}
```

**令牌属于用户**：解码 `access_token`（JWT）的 payload，`sub` 即该用户的平台账号 ID——
它就是平台各内部服务间传递的用户标识（`X-Account-Id` 的值）。关键 claim：

| claim | 含义 |
|-------|------|
| `sub` | 用户平台账号 ID（你要的用户身份） |
| `iss` | 签发方，恒为 `https://www.research.acme.com` |
| `aud` / `scope` / `exp` / `iat` | 资源标识 / 获授权的 scope / 过期与签发时间 |

安全建议：JWT 请用签名校验（RS256 公钥来自 `https://www.research.acme.com/oauth2/jwks`），
并校验 `iss` 与 `exp`；`access_token` 短时效，过期用 `refresh_token` 静默续期：

```
POST /oauth2/token
Authorization: Basic(同上)
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=<refresh_token>
```

## 3. 用 Spring Security 的网站可以零手写接入

如果你的网站是 Spring Boot，直接用标准 OAuth2 客户端配置（无需自己实现上面的流程）：

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          research-sso:
            client-id: <你的 client_id>
            client-secret: <你的 client_secret>
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/auth/callback"
            scope: profile
        provider:
          research-sso:
            authorization-uri: https://www.research.acme.com/oauth2/authorize
            token-uri: https://www.research.acme.com/oauth2/token
            jwk-set-uri: https://www.research.acme.com/oauth2/jwks
```

端点亦可从元数据自动发现：`https://www.research.acme.com/.well-known/oauth-authorization-server`。

## 4. 注意事项

- **一次同意，后续静默**：同一用户对同一应用同意过一次后，再次登录不再弹授权页（拒绝后重新登录会重新询问）。
- **回调地址精确匹配**：query、尾部斜杠都算不同；改地址需联系我们重新登记。
- **PKCE 与 state 是强制的**：服务端强制 PKCE（不带 `code_verifier` 无法兑换授权码）；
  `state` 请务必校验。
- **当前未提供单点登出端点**：登出请先处理你应用自身的会话。
- **开发联调**：测试环境的 issuer 为 `http://localhost:8081`，生产即为上文的
  `https://www.research.acme.com`。
