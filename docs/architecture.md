# work-auth-server 架构设计

本文是本服务的**架构源文件**（source of truth）：描述代码的目标结构与各机制的落点，重构与演进以本文为准。
需求见 [requirements.md](requirements.md)（下文以 FR-*/NFR-* 引用）。

## 1. 总览

```
                    公网源 :8081
                        │
                ┌───────▼────────┐
                │ work-mcp-gateway │  对 agent：OAuth 2.0 资源服务器（校验 JWT：iss/aud/JWKS）
                │                  │  对后端：注入 X-Account-Id；RFC 9728 PRM
                └───┬──────────┬───┘
      注入头 │          │ 注入头（校验过 JWT 的账号）
        ┌───▼─────┐   ┌─▼──────────┐
        │ auth-server │   │ MCP server │   两者都不接触 JWT（JWT 在网关终结，
        │   :9000     │   │  （内部）    │    MCP server 只看到 X-Account-Id）
        └─────────────┘   └────────────┘
```

Spring Boot 4.1 / Spring Security 7.1（授权服务器模块已并入 Spring Security 7.0+）。
纯 OAuth 2.1，授权码一律强制 PKCE、一律经 consent 页面由用户显式同意/拒绝。两类客户端：

- **MCP 客户端**（AI agent）：公共客户端，开放 DCR 自注册（不预置），空闲回收；
- **网站应用**（第三方网站）：预注册机密客户端（`app.web-clients` 配置），用户接入走
  OAuth 2.1 标准的授权码 + PKCE + consent（approve/deny），永不空闲回收。

## 2. 需求 → 机制映射

| 需求 | 机制 | 落点 |
|------|------|------|
| FR-1 可信头身份 | 每请求解析账号头 → `AccountAuthentication` | `identity/AccountIdHeaderAuthenticationFilter` + `identity/AccountService` |
| FR-2/3 SSO 跳转 | HTML 请求的认证入口点，`return_to` 仅由请求推导 | `identity/SsoRedirectAuthenticationEntryPoint` |
| FR-4 授权码+PKCE | 公共客户端 `requireProofKey`；Spring AS 协议端点 | `config/SecurityConfig`（链 1） |
| FR-5 用户显式同意/拒绝 | `consentPage("/oauth2/consent")` + consent 页面（同意提交 scope；拒绝提交空 scope = 内建 deny 语义）；DCR 注册的客户端内建 `requireAuthorizationConsent=true` | `web/ConsentController` + `config/SecurityConfig` |
| FR-6 MCP 客户端不预置 | 客户端仓库对 DCR 空启动（网站应用种子除外），MCP 客户端唯一来源是开放 DCR | `config/AuthorizationServerConfig`（仓库 bean） |
| FR-7 开放 DCR | `openRegistrationAllowed(true)` + 匿名放行 | `config/SecurityConfig`（链 1） |
| FR-8 注册零出网 | DCR 校验器链：redirect_uri 严格 → 拒 `jwks_uri` → scope 自声明 | `client/DcrRegistrationPolicy` |
| FR-9 空闲回收 | 按 `lastSeen` 驱逐的 `RegisteredClientRepository` 装饰器，定时 sweep；预注册网站客户端白名单豁免 | `client/ExpiringRegisteredClientRepository` |
| FR-10 resource 校验 | authorize 请求转换器包装默认实现，归一化比对允许集 | `mcp/ResourceIndicatorAuthenticationConverter` |
| FR-11 aud 盖章 | JWT token customizer | `mcp/McpAudienceTokenCustomizer` |
| FR-12 issuer 硬设 | `AuthorizationServerSettings.issuer = app.issuer` | `config/AuthorizationServerConfig` |
| FR-13 元数据/JWKS | Spring AS 自动发布 | （无自有代码） |
| FR-14 /api/me | 演示端点 | `web/MeController` |
| FR-15 网站应用（预注册机密客户端） | 配置种子 → 机密客户端（HTTP Basic + PKCE 强制 + consent，auth code/refresh），白名单豁免空闲回收 | `client/PreRegisteredClients` + `client/ExpiringRegisteredClientRepository` |
| FR-16 外部客户端凭证校验 | 存储侧标记 `{ext}<clientId>` + 定制 `PasswordEncoder` 委托 REST API（dev 为 `{noop}` 本地比对），挂在内建 `ClientSecretAuthenticationProvider` 上 | `client/ClientCredentialVerifier`、`client/RestClientCredentialVerifier`、`client/ExternalClientSecretPasswordEncoder` |
| NFR-1 无状态 | 两条链 `SessionCreationPolicy.STATELESS`；consent 状态存于 authorization/consent service | `config/SecurityConfig` |
| NFR-3 存储可替换 | 账户/客户端/授权/同意/密钥均以接口注入 | `identity/AccountService`、`RegisteredClientRepository`、`OAuth2AuthorizationService`、`OAuth2AuthorizationConsentService`、`JWKSource` |

## 3. 包结构（目标）

按"能力域"分包，每个 FR 在且仅在一个显而易见的位置：

```
com.work.authserver
├── AuthServerApplication.java        入口（@EnableConfigurationProperties + @EnableScheduling）
├── config/                           —— 装配层（只做 bean 组装，不含策略逻辑）
│   ├── AppProperties.java            app.* 配置属性
│   ├── SecurityConfig.java           两条 SecurityFilterChain；协议端点定制项的接线
│   └── AuthorizationServerConfig.java 客户端仓库（空启动）、签名 JWK、JwtDecoder、ServerSettings、aud customizer
├── identity/                         —— 身份域：可信头解析 + SSO 交接（FR-1/2/3）
│   ├── Account.java                  principal；getName()=account id → token sub
│   ├── AccountAuthentication.java    专用 Authentication 类型
│   ├── AccountService.java           按 account id 解析账户（接口，NFR-3）
│   ├── InMemoryAccountService.java   内存实现：acct-123(alice)、acct-456(bob)
│   ├── AccountIdHeaderAuthenticationFilter.java
│   └── SsoRedirectAuthenticationEntryPoint.java
├── client/                           —— 客户端域：预注册种子、DCR 策略、凭证校验、注册存储（FR-6/7/8/9/15/16）
│   ├── PreRegisteredClients.java     网站应用配置（app.web-clients）→ 机密 RegisteredClient
│   ├── ClientCredentialVerifier.java 外部凭证校验接口（VerifiedClient 契约：accountId 等）
│   ├── RestClientCredentialVerifier.java  REST 实现（POST clientId+clientSecret → accountId）
│   ├── ExternalClientSecretPasswordEncoder.java  {noop} 本地比对 / {ext} 委托外部校验
│   ├── DcrRegistrationPolicy.java    开放注册校验器链（含 jwks_uri 拒绝）
│   └── ExpiringRegisteredClientRepository.java  空启动、空闲回收（预注册白名单豁免）的内存客户端仓库
├── mcp/                              —— MCP/RFC 8707 覆盖层（FR-10/11）
│   ├── ResourceIndicatorAuthenticationConverter.java
│   └── McpAudienceTokenCustomizer.java
└── web/
    ├── ConsentController.java        GET /oauth2/consent —— consent 页面（FR-5）
    └── MeController.java             GET /（存活）、GET /api/me（FR-14）
```

原则：

- `config/` 只做装配；策略逻辑属于各能力域（如 DCR 校验器链在 `client/`，aud 盖章在 `mcp/`）。
- 能力域之间不互相依赖（`mcp/` 与 `client/` 互不可见），都只被 `config/` 引用。
- Web 组件（filter/entry point/页面控制器）与它们服务的能力放在一起：身份交接在 `identity/`，
  consent 页面在 `web/`。

## 4. 过滤器链与请求处置

**链 1（@Order(1)，`authorizationServer.getEndpointsMatcher()`）** — 协议端点
（`/oauth2/authorize|token|register|jwks|…`、`/.well-known/…`）：

1. `SecurityContextHolderFilter` 之后挂 `AccountIdHeaderAuthenticationFilter`：有头且账号存在 → 置
   `AccountAuthentication`；否则保持匿名。
2. `AuthorizationFilter`：`/oauth2/register` 显式 `permitAll`（开放注册，FR-7），其余 `authenticated()`。
3. 匿名 + `/oauth2/authorize` 上的浏览器请求（text/html）→ `SsoRedirectAuthenticationEntryPoint`
   302 到 SSO 带 `return_to`（FR-2）。入口点按路径收窄到 authorize——这是本链唯一的用户侧端点；
   其余协议端点（token/introspect/revoke）是客户端认证的，保持协议错误语义（如 401 invalid_client），
   不做登录重定向。
4. authorize 端点定制：
   - 请求转换器 = `ResourceIndicatorAuthenticationConverter`（FR-10）；
   - `consentPage("/oauth2/consent")`（FR-5）——DCR 注册的客户端被内建地设为
     `requireAuthorizationConsent=true`，授权请求因此转入 consent 步骤；consent 的提交
     （POST `/oauth2/authorize`，`client_id`+`state`+`scope`）由 Spring AS 内建的 consent
     转换器/provider 处理。
5. register 端点定制：开放注册 + `DcrRegistrationPolicy` 校验器链（FR-7/8）。
6. 客户端认证定制（FR-16）：找到内建 `ClientSecretAuthenticationProvider`，把它比对 secret 所用的
   `PasswordEncoder` 换成 `ExternalClientSecretPasswordEncoder`——存储为 `{noop}…` 时本地比对（dev），
   为 `{ext}<clientId>` 时委托外部 REST API（校验失败即 `invalid_client`）。
7. `STATELESS`（NFR-1）。

**链 2（@Order(2)）** — 其余一切（`/api/me`、`/oauth2/consent`、`/error`）：

- `/oauth2/consent` 落在这条链上：**必须已登录才能看到并同意**（匿名则 SSO 跳转），页面由
  `ConsentController` 渲染。
- `/error` `permitAll`（无法回传客户端的授权错误经 `BasicErrorController` 落到这里渲染而非被 SSO
  重定向吞成 404；dev 姿态下错误页暴露原因，NFR-5）。
- 同样的头过滤 + SSO 入口点 + `STATELESS`。

## 5. 关键流程

### 5.1 授权码 + PKCE + consent（经网关，MCP 场景）

```
agent ──GET :8081/oauth2/authorize?client_id&redirect_uri&scope&state&code_challenge(S256)[&resource]──▶
gateway ──注入 X-Account-Id──▶ auth-server
  ├─ 头解析出 Account → 已认证
  ├─ resource 参数命中允许集？（未命中 → 302 redirect_uri?error=invalid_target）
  └─ 客户端 requireAuthorizationConsent=true
     → 302 /oauth2/consent?client_id&scope&state（待同意的授权请求存入 authorization service）
Browser ──GET /oauth2/consent──（网关注入 X-Account-Id；未登录则先走 5.2 的 SSO）──▶ ConsentController 渲染
Browser ──POST /oauth2/authorize (client_id+state+scope[全部勾选])──▶ 内建 consent provider
  ├─ 同意：记录写入 consent service（per 用户+客户端，重复授权不再询问）
  │   → 302 redirect_uri?code=…&state=…
  └─ 拒绝（第二个表单，无 scope 参数 = 空 scope 提交）：撤销已存同意、删除挂起授权
      → 302 redirect_uri?error=access_denied&state=…（RFC 6749 §4.1.2.1，agent 可干净终止）
agent ──POST /oauth2/token (code + code_verifier)──▶ {access_token, refresh_token}
       JWT: iss=<app.issuer> 硬设, aud=<app.mcp.resource>, sub=<account id>
agent ──Authorization: Bearer <jwt>──▶ gateway（资源服务器校验 iss/aud/JWKS）
gateway ──X-Account-Id──▶ MCP server（不接触 JWT）
```

### 5.2 未登录 → SSO → 回跳

```
Browser ──GET /oauth2/authorize|/oauth2/consent|/api/me（无 X-Account-Id / 账号不存在）
auth-server ──302──▶ <app.sso.login-url>?return_to=<原完整 URL>
gateway/dev-SSO 完成登录后再次注入 X-Account-Id 回跳 return_to → 流程继续
```

`return_to` 完全由 `requestURL + queryString` 构造，不含任何用户可控输入（FR-3）。

### 5.3 开放 DCR（零出网）

```
agent ──POST /oauth2/register（JSON，token_endpoint_auth_method=none）──▶
  校验链：DEFAULT_REDIRECT_URI_VALIDATOR（https/loopback 严格）
        → 拒绝 jwks_uri（invalid_client_metadata）    ← 服务器绝不解引用客户端 URL
        → SIMPLE_SCOPE_VALIDATOR（scope 自声明）
  ──201──▶ { client_id, … }（无 secret）；写入 ExpiringRegisteredClientRepository（lastSeen=now）
  注册的客户端内建 requireProofKey=true + requireAuthorizationConsent=true（FR-4/FR-5）
  空闲 > app.dcr.evict-unused-after 且无读触达 → 定时 sweep 回收（FR-9；仓库内所有客户端同规则）
```

### 5.4 网站应用（预注册机密客户端）

```
# 用户接入：OAuth 2.1 标准的授权码 + PKCE + consent（机密客户端同样强制 PKCE 与 consent）
Browser ──GET /oauth2/authorize?client_id=web-app&…&code_challenge=…──▶（网关注入 X-Account-Id）
  └─ consent（同意/拒绝，同 5.1）→ 302 redirect_uri?code=…
site-backend ──POST /oauth2/token（code + code_verifier，
               Authorization: Basic(client_id, client_secret)）──▶ {access_token, refresh_token}
               （token 是用户的：sub=<用户账号>；id+secret 只是客户端认证，证明"我是预注册网站"）
```

预注册客户端在仓库中带白名单标记，定时 sweep 不回收（FR-9）；注册来源是 `app.web-clients`
配置（FR-15；生产演进为管理端 + 持久化 + secret 哈希，见 §9）。secret 的比对（dev 本地 / 生产
外部 REST API，FR-16）发生在客户端认证阶段，两条路径的协议行为完全一致。

## 6. 安全不变量

1. **无状态**：任何链上不允许创建/复用会话；身份只来自当前请求的头。consent 事务以 consent state
   为键存于 authorization service，同意记录存于 consent service——都不依赖 HttpSession（NFR-1）。
2. **显式同意**：任何客户端的授权码发放都必须经过 consent 页面的显式提交（FR-5）——没有
   "跳过 consent" 的旁路（DCR 注册器内建 `requireAuthorizationConsent=true`，配置层不再提供覆盖）。
3. **注册零出网**：注册路径上不存在对客户端提供 URL 的解引用；`jwks_uri` 被显式拒绝（FR-8）。
4. **开放重定向防御**：SSO `return_to` 仅由请求推导（FR-3）；authorize 错误仅重定向到客户端已注册的
   `redirect_uri`（Spring AS 默认行为）。
5. **issuer 稳定**：`iss`/discovery 与到达路径无关，网关按同一 issuer 校验（FR-12）。
6. **资源绑定**：token `aud` 只会是配置允许集内的值（FR-10/11）。

## 7. 测试矩阵

| 测试 | 层级 | 锚定 |
|------|------|------|
| `OAuth2PkceFlowTests` | 真实端口集成 | FR-2（authorize 无头→SSO 带 return_to）、FR-4、FR-5、FR-10（尾斜杠归一化） |
| `ConsentFlowTests` | 真实端口集成 | FR-5（consent 页面重定向、匿名→SSO、页面契约、同意→发码、拒绝→access_denied、拒绝后重新询问、同意按用户+客户端记住） |
| `McpResourceIndicatorTests` | 真实端口集成 | FR-10（允许/拒绝）、FR-11（aud） |
| `TokenIssuerTests` | 真实端口集成 | FR-12（iss 硬设）、FR-11 |
| `DcrTests` | 真实端口集成 | FR-6/7（注册→consent→完整流）、FR-8（jwks_uri 拒绝）、FR-11 |
| `WebAppClientFlowTests` | 真实端口集成 | FR-15（secret 认证、机密客户端强制 PKCE、consent、refresh_token） |
| `ExternalClientRegistryTests` | 真实端口集成（HTTP stub） | FR-16（外部 API 裁决凭证、配置 secret 被忽略、错误回传、用户流照常） |
| `SecurityFilterChainTests` | 真实端口集成 | FR-1/2（头认证 vs SSO 跳转） |
| `ExpiringRegisteredClientRepositoryTests` | 纯单元（注入时钟） | FR-9（空闲回收；预注册白名单豁免） |
| `PreRegisteredClientsTests` | 纯单元 | FR-15（配置 → 机密客户端不变量；两种 secret 存储模式） |
| `ExternalClientSecretPasswordEncoderTests` / `RestClientCredentialVerifierTests` | 纯单元 | FR-16（{noop}/{ext} 分派、REST 成功/失败/不可达） |
| `ResourceIndicatorAuthenticationConverterTests` | 纯单元 | FR-10 归一化/拒绝/关闭 |
| `SsoRedirectAuthenticationEntryPointTests` | 纯单元 | FR-2/3 Location 构造 |

集成测试用真实 HTTP（JDK HttpClient）而非 MockMvc——MockMvc 无法驱动 `/oauth2/authorize`；
集成测试统一从 DCR 注册开始（FR-6：无预置客户端可复用）。单元测试覆盖纯逻辑，秒级、无容器。

## 8. 配置参考（`app.*`）

| 键 | 默认 | 语义 |
|----|------|------|
| `app.issuer` | `http://localhost:8081` | `iss` + discovery 地址（硬设，FR-12） |
| `app.header.name` | `X-Account-Id` | 可信账号头（FR-1；网关对 auth-server 与 MCP server 注入同一头） |
| `app.sso.login-url` | `https://sso.example.com/login` | 未登录跳转目标（FR-2；dev 指向网关 mock-SSO） |
| `app.sso.return-to-param` | `return_to` | 回跳参数名（FR-2） |
| `app.mcp.resource` | `http://localhost:8081` | 允许的 `resource` + token `aud`（FR-10/11；留空关闭校验） |
| `app.dcr.evict-unused-after` | `1h` | 空闲注册回收时长（FR-9；预注册网站客户端豁免） |
| `app.web-clients` | dev 内置 `web-app-demo` | 预注册网站应用列表（client-id/secret/name/redirect-uris/scopes，FR-15） |
| `app.client-registry.enabled` | `false` | 启用外部客户端凭证校验（FR-16）；启用后 `app.web-clients[].client-secret` 不再参与比对 |
| `app.client-registry.url` | （无） | 校验 API 地址（enabled 时必填）：POST {clientId, clientSecret} → 2xx + accountId 即有效 |

服务器端口 `:9000`、`forward-headers-strategy: native`（网关后 TLS 终结时修正 scheme）见 `application.yml`。

## 9. 已知限制与演进路线

| 主题 | 现状 | 演进 |
|------|------|------|
| 持久化 | 客户端/授权/同意/密钥全内存，重启即失（refresh token、已同意记录、动态注册丢失） | 换 JDBC `RegisteredClientRepository`/`OAuth2AuthorizationService`/`OAuth2AuthorizationConsentService`/持久 `JWKSource`（NFR-3 接口已就位） |
| 网站应用 secret | 以明文存于 `app.web-clients` 配置（dev 姿态），无管理界面 | 生产：注册管理端 + secret 哈希存储（随持久化一起落地）；或直接启用外部校验（FR-16），secret 完全由外部 API 持有 |
| accountId 用法 | 外部校验返回的 accountId 暂未写入令牌（仅校验结果契约） | 按需评估：为该客户端的用户令牌加盖"客户端所属账号"claim |
| 多 resource | `aud` 固定单值 | converter 已按允许集（`Set`）实现；customizer 改为绑 per-request `resource`（需在 authorization 记录中保存该参数） |
| 真实 SSO | 网关 dev `?account=` 旁路 | 网关侧接签名断言/会话 cookie；本服务不变（信任边界仍是"网关注入的头"） |
| DCR scope | 自声明 | 换严格 allowlist 校验器（`DcrRegistrationPolicy` 单点修改） |
| OIDC | 关闭 | `authorizationServer.oidc(withDefaults())` + 客户端加 `openid` scope |
| 错误页 | dev 姿态暴露原因 | prod 换脱敏错误页 |
