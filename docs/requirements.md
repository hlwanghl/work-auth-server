# work-auth-server 需求说明

本文是本服务的**需求源文件**（source of truth）：代码行为与本文件冲突时，以本文件为准或先改本文件再改代码。
配套的架构设计见 [architecture.md](architecture.md)。

## 1. 背景与定位

- 本服务是一个 **OAuth 2.1 授权服务器（Authorization Server）**，为 **MCP（Model Context Protocol）**
  生态签发访问令牌：MCP 客户端（AI agent）通过标准 OAuth 流程拿到 JWT。
- **部署形态**：`work-auth-server` 与 **MCP server 都位于 `work-mcp-gateway`（`:8081`，公网唯一入口）
  之后**，二者都是内部后端。**用户的身份统一由网关解析**：网关对已登录用户把账号 id 注入
  `X-Account-Id` 请求头转发给后端——本服务用它确认资源拥有者，MCP server 也用它确认访问者。
- **JWT 只在网关终结**：MCP 客户端把 JWT 呈现给**网关**（网关就是 OAuth 2.0 resource server，按
  issuer/audience/JWKS 校验令牌），校验通过后网关向 MCP server 注入 `X-Account-Id`——
  **MCP server 不接触 JWT**。本服务签发的令牌只需对网关的校验口径正确。

## 2. 功能需求

### 身份与登录

- **FR-1 可信头身份解析**：网关对已登录用户注入账号头（默认 `X-Account-Id`）。本服务从该头解析用户，
  账号必须真实存在（能解析成 Account）才视为已认证；account id 将成为所签发令牌的 `sub`。
- **FR-2 未登录跳转 SSO**：头缺失或账号不存在时，浏览器请求 302 到外部 SSO 登录页，并携带
  `return_to=<原始完整 URL>`（含全部查询参数，例如完整的 `/oauth2/authorize?…&code_challenge=…`），
  SSO 登录后把用户送回原请求，OAuth 流程无缝继续。程序化请求（如 token 端点）不跳转，返回标准 OAuth 错误。
- **FR-3 return_to 不可作为开放重定向跳板**：跳转目标 URL 只能由请求本身推导，绝不采信任何用户输入。

### OAuth 2.1 协议

- **FR-4 授权码 + PKCE**：公共客户端（`token_endpoint_auth_method=none`，无 secret），**强制 PKCE**
  （`requireProofKey=true`），支持 `authorization_code` 与 `refresh_token` 两种 grant。
- **FR-5 用户显式同意或拒绝（consent）**：授权流程必须经过 consent 页面——向用户展示客户端标识与
  所申请的 scope。**用户明确同意后才能继续并发放授权码**；**用户也可显式拒绝**：拒绝后客户端按
  RFC 6749 §4.1.2.1 收到 `error=access_denied`（带回原 `state`），挂起的授权被清理、已保存的同意
  记录（如有）被撤销，再次授权重新走 consent。所有客户端一律要求 consent（动态注册客户端由注册
  流程内置 `requireAuthorizationConsent=true`）。consent 不依赖服务端会话（无会话架构，见 NFR-1）。
  同一用户对同一客户端的同意可被记住（per-principal+client 记录）。不启用 OIDC（纯 OAuth 2.1）。
- **FR-6 不预置客户端**：本服务**不内置任何静态客户端**。所有客户端（MCP client）一律经 FR-7 的
  DCR 动态注册获得 `client_id`。
- **FR-7 动态客户端注册（RFC 7591，开放注册）**：任意 agent 可匿名 `POST /oauth2/register` 自注册公共
  PKCE 客户端，立即用于授权流程；返回 201 与 `client_id`，不含 secret；scope 允许自声明（`mcp:*` 场景）；
  `redirect_uri` 严格校验（https / loopback）。开放注册在 prod 保持开放（agent-native 产品的前提），
  靠限流与回收来加固，而不是关掉。
- **FR-8 注册零出网（不变量）**：注册过程中本服务**绝不请求客户端提供的任何 URL**。`jwks_uri` 一律拒绝
  （`invalid_client_metadata`）——"不接受按引用的客户端密钥"是强制不变量，而非当前实现的巧合，杜绝未来
  引入机密客户端时悄悄打开 SSRF/出网面。
- **FR-9 空闲注册回收**：客户端（均为动态注册，见 FR-6）若持续空闲（默认 1 小时内未被任何读操作触达）
  则被回收；读 = 续命（authorize/token/introspect 都算）。这是开放注册的防泛滥手段（另一手段是网关对
  `/oauth2/register` 的 per-IP 限流）。

### 令牌与资源绑定（MCP）

- **FR-10 RFC 8707 resource 校验**：授权请求的 `resource` 参数必须命中允许集（配置的 MCP resource），
  否则以 `invalid_target` 拒绝（错误重定向回客户端合法的 `redirect_uri`）。缺省 `resource` 允许通过。
  比较做**归一化**：`http://host:port` 与 `http://host:port/` 视为同一 resource（RFC 3986：空路径等价 `/`），
  兼容会补根斜杠的通用客户端（如 MCP Inspector）。
- **FR-11 令牌资源绑定**：签发的 JWT access token 的 `aud` = 配置的 MCP resource。
  **校验方是网关**（作为资源服务器校验 iss/aud/JWKS，见 §1）；MCP server 不接触令牌。
- **FR-12 issuer 稳定**：`iss` 与全部 discovery 端点地址**硬设**为公网源（`app.issuer`，即网关地址），
  与请求实际到达路径（`:9000` 直连或经网关）无关；网关对令牌按此 issuer 校验。
- **FR-13 元数据与密钥发布**：发布 RFC 8414 授权服务器元数据（含 `registration_endpoint`）与
  `/oauth2/jwks` 签名公钥。

### 开发/验证接口

- **FR-14 身份自省端点**：`GET /api/me` 返回当前解析出的账号（id、用户名、authorities），用于验证
  「头 → 账户」链路与 SSO 跳转行为；`GET /` 为存活检查。

## 3. 非功能需求

- **NFR-1 无状态**：两个过滤器链均为 `STATELESS`——身份按请求解析，绝不落 `HttpSession`，否则头认证的
  身份会跨请求泄漏。consent 事务不依赖会话：待同意的授权请求存于内存 `OAuth2AuthorizationService`
  （以 consent state 为键），同意记录存于 `OAuth2AuthorizationConsentService`（per 用户+客户端）。
- **NFR-2 信任边界**：本服务**只应接受来自网关的请求**（部署层保证：仅网关能注入账号头）。
  头名、SSO URL、return 参数名、issuer、MCP resource、回收时长全部可配置（`app.*`）。
- **NFR-3 存储可替换**：账户、客户端、授权/同意记录、签名密钥当前均为内存实现（重启即失），但必须以
  接口隔离（`AccountService` / `RegisteredClientRepository` / `OAuth2AuthorizationService` /
  `OAuth2AuthorizationConsentService` / `JWKSource`），生产替换为持久化实现时不动协议层代码。
- **NFR-4 测试策略**：协议行为用**真实端口集成测试**覆盖（MockMvc 无法驱动 `/oauth2/authorize`）；
  纯逻辑（resource 归一化、SSO 跳转构造、回收规则）用**无容器单元测试**覆盖。集成测试统一走
  「DCR 注册 → authorize → consent → token」的完整 agent 路径，与本服务无预置客户端（FR-6）一致。
- **NFR-5 可诊断**：dev 环境错误页暴露真实错误原因（无法回传客户端的授权错误会落到 `/error`，
  生产环境需替换为脱敏错误页）。

## 4. 明确不做（Out of scope）

| 项 | 说明 |
|----|------|
| OIDC | 纯 OAuth 2.1；未来扩展点 |
| scope 粒度的部分同意 | consent 页 scope 默认全选；勾选部分提交会再次询问，不做独立的"部分授权"确认 UI |
| 多 resource 的 per-request `aud` 绑定 | 当前单 MCP resource，`aud` 固定；列为架构扩展点 |
| 真实 SSO 集成 | 网关侧 dev resolver（`?account=`）模拟；真实 SSO 断言/会话回跳是网关侧工作 |
| 持久化存储 | 客户端/授权/同意/密钥均在内存，生产前必须替换（NFR-3 已预留接口） |

## 5. 验收口径

- 上述 FR 全部有自动化测试锚定（映射见 [architecture.md](architecture.md) §7 测试矩阵）。
- 代码变更以本文件与 [architecture.md](architecture.md) 为准：先改文档（需求变更需在此留痕），
  再让代码与测试向文档对齐。
