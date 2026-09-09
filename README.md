# work-auth-server

A Spring Authorization Server built on **Spring Boot 4.1 / Spring Security 7.1** (the authorization
server is now a module inside Spring Security 7.0+) for **MCP (Model Context Protocol) authorization**:

1. **Resolves the current user from an HTTP header** (`X-Account-Id`) — a trusted gateway/proxy
   injects the account id for already-authenticated users; missing/unknown → **redirect to an external
   SSO** with `return_to`, and back to the original request after login.
2. **OAuth 2.1 Authorization Code + PKCE** for public **and** confidential clients (PKCE mandatory,
   no OIDC), with a **mandatory consent page** — the user explicitly approves or denies the requested
   scopes before the client hears anything (deny → `error=access_denied` back to the client).
3. **RFC 8707 resource-bound JWT access tokens** for an AI agent (MCP client) — the `resource` request
   parameter is validated and the MCP server's URL is stamped as the token `aud`.
4. **Two client onboarding paths**: MCP agents self-register via **RFC 7591 open DCR** (public clients,
   zero-egress registration, idle reaping); **website apps are pre-registered** as confidential clients
   (config-seeded secret, never reaped). There are no preset MCP clients; the M2M `client_credentials`
   grant is intentionally not offered (see docs/requirements.md FR-15).

> Requires **Java 17+**. Built with Gradle.

## Documentation

The requirements and the architecture are **source files** — code changes go through them:

| Doc | Content |
|-----|---------|
| [docs/requirements.md](docs/requirements.md) | Functional requirements (FR-1…FR-16), non-functional requirements, out-of-scope list, acceptance rules |
| [docs/architecture.md](docs/architecture.md) | Requirement→mechanism map, package structure, filter chains, key flows, security invariants, test matrix, config reference, evolution roadmap |
| [docs/sso-guide.md](docs/sso-guide.md) | Integration guide for website teams using this service as SSO (Chinese) |

## Deployment

This server is an **internal backend on `:9000`**, fronted by [`work-mcp-gateway`](../work-mcp-gateway)
(`:8081`, the single public origin). The **gateway resolves the user** for both backends and injects
`X-Account-Id` (dev: `?account=` resolver) — this server uses it to identify the resource owner on the
authorize flow, and the MCP server uses it to identify the caller. The **gateway is also the OAuth2
resource server**: it validates the JWTs issued here (issuer `http://localhost:8081`) and relays the
account to the MCP server as `X-Account-Id` — **the MCP server never sees the JWT**. Direct `:9000`
access is dev/internal only. See docs/architecture.md §1 for the topology.

```
Browser ──GET /oauth2/authorize?…&code_challenge=…──▶ gateway :8081 ──▶ auth-server :9000 (no X-Account-Id)
                                                              │ anonymous (text/html)
                                                              ▼
                                              302 → :8081/dev-sso/login?return_to=/oauth2/authorize?…
                                                              │ mock-SSO "logs in" + 302 back
Browser ──GET /oauth2/authorize?…── (gateway injects X-Account-Id; header resolved → authenticated)
                                                              │ requireAuthorizationConsent=true
                                                              ▼
Browser ◀──302 /oauth2/consent?client_id&scope&state── (user explicitly approves or denies the scopes)
Browser ──POST /oauth2/authorize (client_id+state+scope)──▶ 302 to client redirect_uri?code=…
         (拒绝/deny submits the form without scopes → redirect_uri?error=access_denied&state=…)
Browser ──POST /oauth2/token (code + code_verifier)──▶ access_token (JWT, iss/aud = http://localhost:8081)
agent ──Authorization: Bearer <jwt>──▶ gateway (validates iss/aud/JWKS) ──X-Account-Id──▶ MCP server
```

## Run

```bash
./gradlew bootRun          # starts on http://localhost:9000 (internal backend)
```

Quick checks (direct on the internal `:9000`, simulating the trusted-proxy header by hand):

```bash
curl -i http://localhost:9000/api/me                                  # no header -> 302 to the SSO login-url
curl -i -H 'X-Account-Id: acct-123' http://localhost:9000/api/me      # header present -> authenticated (alice)
curl -i -H 'X-Account-Id: nobody' http://localhost:9000/api/me        # unknown account -> 302 to SSO
curl -s http://localhost:9000/oauth2/jwks                             # token signing keys
```

Through the gateway (`:8081`, the public front door):

```bash
curl -i "http://localhost:8081/api/me?account=acct-123"   # gateway injects X-Account-Id: acct-123
curl -s http://localhost:8081/.well-known/oauth-authorization-server   # RFC 8414 metadata (incl. registration_endpoint)
```

## Clients

### MCP clients — self-register via open DCR

There are **no preset MCP clients**. An MCP agent registers itself at the open registration endpoint and
then runs the auth-code + PKCE flow with consent (a browser shows the consent page at
`/oauth2/consent` with 同意/拒绝; approvals are remembered per user + client, denials are returned to
the client as `error=access_denied`):

```bash
curl -s -X POST http://localhost:8081/oauth2/register -H 'Content-Type: application/json' -d '{
  "client_name": "my-agent",
  "redirect_uris": ["http://127.0.0.1:8765/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "scope": "mcp:tools mcp:resources"
}'
# -> 201 with a client_id (public client, PKCE, consent required); no client_secret
```

### Website apps — pre-registered confidential clients

A third-party website registers **ahead of time** in `application.yml` (`app.web-clients`), not via DCR.
Its users sign in through the OAuth 2.1 standard flow — authorization code + PKCE + consent (browser
flow, same consent page); the id+secret only **authenticates the client** when it redeems the user's
code, so the resulting tokens belong to the user (`sub` = user account). Secret authentication is
`client_secret_basic` (HTTP Basic) only — per the latest OAuth 2.1 draft; the `client_credentials`
grant is intentionally not offered. Pre-registered clients are exempt from idle reaping.

Secret verification is pluggable (FR-16): in dev the configured secret is compared locally; with
`app.client-registry.enabled=true` the presented (clientId, clientSecret) is POSTed to your own REST
API, whose verdict (2xx + accountId) decides — the configured secrets are then unused, and a
rejection surfaces as plain `invalid_client`:

```yaml
app:
  web-clients:
    - client-id: web-app-demo
      client-secret: web-demo-secret     # dev-grade; prod needs hashed secrets + persistence
      client-name: Demo Website App
      redirect-uris: ["http://127.0.0.1:9090/login/oauth2/code/web-app-demo"]
      scopes: profile
```

```yaml
# production posture: let your own REST API decide whether the credentials are valid (FR-16)
app:
  client-registry:
    enabled: true
    url: http://client-registry.internal/api/verify
```

## Project layout

```
src/main/java/com/work/authserver/
  AuthServerApplication.java            entry point
  config/                               assembly only — beans and filter chains
    AppProperties.java                  app.* configuration properties
    SecurityConfig.java                 two filter chains; protocol-endpoint wiring
    AuthorizationServerConfig.java      client store, signing JWK, JwtDecoder, issuer, aud customizer
  identity/                             trusted-header identity + SSO hand-off (FR-1/2/3)
    Account.java / AccountAuthentication.java
    AccountService.java / InMemoryAccountService.java
    AccountIdHeaderAuthenticationFilter.java
    SsoRedirectAuthenticationEntryPoint.java
  client/                               client registry: pre-registered web apps & open DCR (FR-6/7/8/9/15/16)
    PreRegisteredClients.java           app.web-clients config -> confidential RegisteredClients
    ClientCredentialVerifier.java       external credential check contract (accountId, FR-16)
    RestClientCredentialVerifier.java   REST implementation (POST clientId+clientSecret)
    ExternalClientSecretPasswordEncoder.java  {noop} local compare / {ext} external delegation
    DcrRegistrationPolicy.java          DCR validator chain (strict redirect URIs, jwks_uri rejected)
    ExpiringRegisteredClientRepository.java  empty-start in-memory store with idle eviction (web apps whitelisted)
  mcp/                                  RFC 8707 resource-indicator overlay (FR-10/11)
    ResourceIndicatorAuthenticationConverter.java
    McpAudienceTokenCustomizer.java
  web/
    ConsentController.java              GET /oauth2/consent — the consent page (FR-5)
    MeController.java                   GET / (alive) and GET /api/me (identity echo)
```

## Tests

```bash
./gradlew test
```

Real-port integration tests (JDK `HttpClient`, not MockMvc — it cannot drive `/oauth2/authorize`)
cover the protocol behaviour the way real clients experience it: MCP flows start from DCR
registration (no static clients to reuse) and go through the consent step to the token endpoint —
full auth-code + PKCE (`OAuth2PkceFlowTests`), the consent page itself (`ConsentFlowTests`),
header vs SSO redirect (`SecurityFilterChainTests`), RFC 8707 `resource` validation and `aud` stamping
(`McpResourceIndicatorTests`), the hard-set issuer (`TokenIssuerTests`), and open DCR end-to-end
(`DcrTests`). Website apps run as the pre-registered confidential client — secret auth, mandatory
PKCE, consent and refresh tokens (`WebAppClientFlowTests`), with an external registry deciding the
credentials (`ExternalClientRegistryTests`). Pure unit tests
cover the tricky logic without a container: resource normalization, SSO `return_to` construction,
idle eviction with the pre-registered whitelist (injectable clock), and the pre-registered-client
shape. The full matrix is in docs/architecture.md §7.
