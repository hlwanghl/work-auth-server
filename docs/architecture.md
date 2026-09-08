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
纯 OAuth 2.1：公共客户端、授权码 + PKCE、无 OIDC；**所有客户端经 DCR 动态注册（不预置），
授权一律经 consent 页面由用户显式同意**。

## 2. 需求 → 机制映射

| 需求 | 机制 | 落点 |
|------|------|------|
| FR-1 可信头身份 | 每请求解析账号头 → `AccountAuthentication` | `identity/AccountIdHeaderAuthenticationFilter` + `identity/AccountService` |
| FR-2/3 SSO 跳转 | HTML 请求的认证入口点，`return_to` 仅由请求推导 | `identity/SsoRedirectAuthenticationEntryPoint` |
| FR-4 授权码+PKCE | 公共客户端 `requireProofKey`；Spring AS 协议端点 | `config/SecurityConfig`（链 1） |
| FR-5 用户显式同意/拒绝 | `consentPage("/oauth2/consent")` + consent 页面（同意提交 scope；拒绝提交空 scope = 内建 deny 语义）；DCR 注册的客户端内建 `requireAuthorizationConsent=true` | `web/ConsentController` + `config/SecurityConfig` |
| FR-6 不预置客户端 | 客户端仓库空启动，唯一来源是 DCR | `config/AuthorizationServerConfig`（仓库 bean） |
| FR-7 开放 DCR | `openRegistrationAllowed(true)` + 匿名放行 | `config/SecurityConfig`（链 1） |
| FR-8 注册零出网 | DCR 校验器链：redirect_uri 严格 → 拒 `jwks_uri` → scope 自声明 | `client/DcrRegistrationPolicy` |
| FR-9 空闲回收 | 按 `lastSeen` 驱逐的 `RegisteredClientRepository` 装饰器，定时 sweep | `client/ExpiringRegisteredClientRepository` |
| FR-10 resource 校验 | authorize 请求转换器包装默认实现，归一化比对允许集 | `mcp/ResourceIndicatorAuthenticationConverter` |
| FR-11 aud 盖章 | JWT token customizer | `mcp/McpAudienceTokenCustomizer` |
| FR-12 issuer 硬设 | `AuthorizationServerSettings.issuer = app.issuer` | `config/AuthorizationServerConfig` |
| FR-13 元数据/JWKS | Spring AS 自动发布 | （无自有代码） |
| FR-14 /api/me | 演示端点 | `web/MeController` |
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
├── client/                           —— 客户端域：开放 DCR 策略、注册存储（FR-7/8/9）
│   ├── DcrRegistrationPolicy.java    开放注册校验器链（含 jwks_uri 拒绝）
│   └── ExpiringRegisteredClientRepository.java  空启动、空闲回收的内存客户端仓库
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
3. 匿名 + 浏览器请求 → `SsoRedirectAuthenticationEntryPoint` 302 到 SSO 带 `return_to`（FR-2）；
   程序化请求走默认 OAuth2 错误入口点。
4. authorize 端点定制：
   - 请求转换器 = `ResourceIndicatorAuthenticationConverter`（FR-10）；
   - `consentPage("/oauth2/consent")`（FR-5）——DCR 注册的客户端被内建地设为
     `requireAuthorizationConsent=true`，授权请求因此转入 consent 步骤；consent 的提交
     （POST `/oauth2/authorize`，`client_id`+`state`+`scope`）由 Spring AS 内建的 consent
     转换器/provider 处理。
5. register 端点定制：开放注册 + `DcrRegistrationPolicy` 校验器链（FR-7/8）。
6. `STATELESS`（NFR-1）。

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
| `SecurityFilterChainTests` | 真实端口集成 | FR-1/2（头认证 vs SSO 跳转） |
| `ExpiringRegisteredClientRepositoryTests` | 纯单元（注入时钟） | FR-9 |
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
| `app.dcr.evict-unused-after` | `1h` | 空闲注册回收时长（FR-9） |

服务器端口 `:9000`、`forward-headers-strategy: native`（网关后 TLS 终结时修正 scheme）见 `application.yml`。

## 9. 已知限制与演进路线

| 主题 | 现状 | 演进 |
|------|------|------|
| 持久化 | 客户端/授权/同意/密钥全内存，重启即失（refresh token、已同意记录、动态注册丢失） | 换 JDBC `RegisteredClientRepository`/`OAuth2AuthorizationService`/`OAuth2AuthorizationConsentService`/持久 `JWKSource`（NFR-3 接口已就位） |
| 多 resource | `aud` 固定单值 | converter 已按允许集（`Set`）实现；customizer 改为绑 per-request `resource`（需在 authorization 记录中保存该参数） |
| 真实 SSO | 网关 dev `?account=` 旁路 | 网关侧接签名断言/会话 cookie；本服务不变（信任边界仍是"网关注入的头"） |
| DCR scope | 自声明 | 换严格 allowlist 校验器（`DcrRegistrationPolicy` 单点修改） |
| OIDC | 关闭 | `authorizationServer.oidc(withDefaults())` + 客户端加 `openid` scope |
| 错误页 | dev 姿态暴露原因 | prod 换脱敏错误页 |
