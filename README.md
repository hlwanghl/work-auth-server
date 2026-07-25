# work-auth-server

A Spring Authorization Server built on **Spring Boot 4.1 / Spring Security 7.1** (the authorization
server is now a module inside Spring Security 7.0+) that:

1. **Resolves the current user from an HTTP header** (`X-Account-Id`) — a trusted gateway/proxy
   injects the account id for already-authenticated users.
2. **Redirects to an external SSO** when the header is missing or the account is unknown, with a
   `return_to` parameter, and **redirects back** to the original request afterwards (preserving the
   full `/oauth2/authorize?…&code_challenge=…` request).
3. Supports **OAuth 2.1 Authorization Code + PKCE** for a public client (PKCE mandatory).
4. Issues **resource-bound JWT access tokens** for an AI agent (**MCP client**) — an RFC 8707
   resource-indicator overlay that stamps the MCP server's URL as the token `aud` and validates the
   `resource` request parameter. See [Authorizing an AI agent (MCP)](#authorizing-an-ai-agent-mcp).
5. Supports **RFC 7591 Dynamic Client Registration** (open registration) so any agent can
   self-register a `client_id` on first connect.

> Requires **Java 17+**. Built with Gradle.

> **Now fronted by [`work-mcp-gateway`](../work-mcp-gateway) (`:8081`).** This server boots on `:9000`
> as an **internal backend**; callers reach it through the gateway's single public origin. Tokens are
> stamped `iss = http://localhost:8081`, and the gateway injects the `X-Account-Id` on the authorize
> flow (dev resolver). Direct `:9000` access is dev/internal only.

## How authentication works

```
Browser ──GET /oauth2/authorize?…&code_challenge=…──▶ gateway :8081 ──▶ auth-server :9000 (no X-Account-Id)
                                                              │ anonymous
                                                              ▼
                                              302 → https://sso.example.com/login
                                                    ?return_to=http://localhost:8081/oauth2/authorize?…
                                                              │ user logs in at SSO  (dev: ?account=<id> bypass)
                                                              ▼
Browser ◀──302 back to /oauth2/authorize?…── (gateway now injects X-Account-Id: acct-123)
                                                              │ header resolved → authenticated
                                                              ▼
Browser ◀──302 to client redirect_uri?code=…────────────────┘
Browser ──POST /oauth2/token (code + code_verifier)──────────▶  access_token (JWT, iss/aud = http://localhost:8081)
```

**Key assumption (now satisfied):** a gateway/reverse proxy in front of this server injects the
`X-Account-Id` header for users the SSO has authenticated. That proxy is **`work-mcp-gateway`**, which
resolves the user on the `/oauth2/authorize` flow (dev: `?account=`) and forwards `Host: localhost:8081`
(`PreserveHostHeader`). The server trusts that header to identify the resource owner. Configure the
header name, SSO URL and return-parameter in `application.yml`:

```yaml
server:
  forward-headers-strategy: native   # honour X-Forwarded-* behind the gateway / TLS termination
app:
  issuer: http://localhost:8081      # public origin (the gateway) -> token `iss` + discovery addresses (hard-set)
  header:
    name: X-Account-Id
  sso:
    login-url: https://sso.example.com/login
    return-to-param: return_to
  mcp:
    resource: http://localhost:8081   # MCP server's resource identifier -> token `aud` + allowed `resource`
```

Two things make behind-the-gateway operation correct and safe:

* **Hard-set issuer** (`AuthorizationServerSettings.issuer = app.issuer`) — the `iss` claim and all
  discovery endpoint addresses are `http://localhost:8081` regardless of the `Host`/`X-Forwarded-*`
  headers a request arrives with, so they are stable across proxy hops. (`PreserveHostHeader` on the
  gateway still keeps request-derived URLs like the SSO `return_to` on `:8081`.)
* **Stateless sessions** (`SessionCreationPolicy.STATELESS` on both filter chains) — without this,
  header-authenticated identity would leak across requests via `HttpSession` once a principal is set.
  Safe here because consent is disabled (no session-bound consent/authorization state; codes live in
  the in-memory `OAuth2AuthorizationService`).

## Run

```bash
./gradlew bootRun          # starts on http://localhost:9000 (internal backend)
```

This server is **internal**; in a real deployment callers reach it through `work-mcp-gateway` (`:8081`).
In local dev you can still hit `:9000` directly to inspect it.

Quick checks (direct on the internal `:9000`, simulating the trusted-proxy header by hand):

```bash
# No header -> redirected to the external SSO (with return_to)
curl -i http://localhost:9000/api/me

# Header present -> authenticated
curl -i -H 'X-Account-Id: acct-123' http://localhost:9000/api/me

# Unknown account -> also redirected to SSO
curl -i -H 'X-Account-Id: nobody' http://localhost:9000/api/me

# Token signing keys published
curl -s http://localhost:9000/oauth2/jwks
```

Through the gateway (`:8081`), the `X-Account-Id` is injected for you (dev: `?account=`):

```bash
curl -i "http://localhost:8081/api/me?account=acct-123"   # gateway injects X-Account-Id: acct-123
curl -i http://localhost:8081/api/me                      # no ?account -> SSO redirect
```

## Registered clients

### demo-client

| field        | value                                                |
|--------------|------------------------------------------------------|
| client_id    | `demo-client`                                        |
| auth method  | `none` (public client → PKCE required, no secret)    |
| grant types  | `authorization_code`, `refresh_token`                |
| redirect_uri | `http://127.0.0.1:8080/login/oauth2/code/demo-client`, `https://oauth.pstmn.io/v1/callback` |
| scopes       | `read`, `write` (no `openid` → pure OAuth 2.1)       |

### mcp-agent

An AI agent (MCP client) that obtains tokens for the MCP server.

| field        | value                                                |
|--------------|------------------------------------------------------|
| client_id    | `mcp-agent`                                          |
| auth method  | `none` (public client → PKCE required, no secret)    |
| grant types  | `authorization_code`, `refresh_token`                |
| redirect_uri | `http://127.0.0.1:8080/callback`, `http://localhost:3000/callback` |
| scopes       | `mcp:tools`, `mcp:resources`                         |

## Project layout

```
src/main/java/com/work/authserver/
  AuthServerApplication.java            entry point
  config/
    AppProperties.java                  app.header.name, app.sso.*
    AuthorizationServerConfig.java      demo client, RSA signing key, JwtDecoder
    SecurityConfig.java                 two filter chains + header filter + SSO entry point
  security/
    AccountIdHeaderAuthenticationFilter.java
    SsoRedirectAuthenticationEntryPoint.java
    McpResourceIndicatorAuthenticationConverter.java   RFC 8707 `resource` param validation
  user/
    Account.java                        principal (account id -> JWT `sub`)
    AccountService.java                 resolve-by-account-id interface
    InMemoryAccountService.java         demo accounts: acct-123 (alice), acct-456 (bob)
  web/MeController.java                 GET / and /api/me
```

## Tests

```bash
./gradlew test
```

`OAuth2PkceFlowTests` drives the full authorization-code + PKCE flow end-to-end (authorize with a
generated `code_challenge` and the `X-Account-Id` header → exchange `code` + `code_verifier` at the
token endpoint → asserts a JWT access token). `SecurityFilterChainTests` checks the header-vs-SSO
redirect behaviour. `McpResourceIndicatorTests` asserts the access-token `aud` equals the configured
MCP resource and that the `resource` param is accepted/rejected per the allowlist. `DcrTests`
registers a client via RFC 7591 and then runs the full auth-code + PKCE flow with it.

Both test classes run as real-port integration tests (`@SpringBootTest(RANDOM_PORT)` + the JDK
`HttpClient`), not under MockMvc — MockMvc cannot drive the `/oauth2/authorize` endpoint (its
request converter rejects the well-formed request), and the official Spring sample likewise tests
`/oauth2/token` via MockMvc but drives the authorize flow through a real client.

## Authorizing an AI agent (MCP)

MCP (Model Context Protocol) authorization is OAuth 2.1 + PKCE — exactly what this server issues —
so an AI agent (the MCP client) does the standard auth-code + PKCE flow and presents the resulting
JWT to the **MCP server**, which runs as a separate OAuth2 resource server validating these tokens.

The MCP 2025-06-18 spec also requires **RFC 8707 resource indicators** (the `resource` parameter
and resource-bound tokens). **Spring Authorization Server 7.1 has no native RFC 8707 support**, so
it is implemented here as a thin overlay:

- **`app.mcp.resource`** is the MCP server's resource identifier (its base URL).
- `McpResourceIndicatorAuthenticationConverter` validates the `resource` request parameter against
  that value — a request for any other resource is rejected with `error=invalid_target`.
- `mcpAudienceTokenCustomizer` stamps that value as the access token's `aud` (the claim the MCP
  resource server validates).

```
agent ──GET /oauth2/authorize?...&resource=http://localhost:8081&code_challenge=…──▶ gateway :8081 ──▶ auth-server
auth-server ──302 ?code=… (X-Account-Id resolves the user via SSO)──▶ agent
agent ──POST /oauth2/token (code + verifier)──▶ access_token (JWT, iss/aud=http://localhost:8081)
agent ──MCP request, Authorization: Bearer <jwt>──▶ gateway (resource server, validates iss/aud+JWKS) ──▶ MCP server
```

Endpoints the agent needs are auto-published (reachable on the public `:8081`; same paths on internal
`:9000`):

```bash
curl -s http://localhost:8081/.well-known/oauth-authorization-server   # RFC 8414 metadata (incl. registration_endpoint)
curl -s http://localhost:8081/oauth2/jwks                              # token signing keys
```

### Dynamic Client Registration (RFC 7591)

Any agent can self-register a `client_id` (no pre-shared secret) at `/oauth2/register`, then
immediately run the auth-code + PKCE flow with it. Through the gateway (`:8081`, the public front
door):

```bash
curl -s -X POST http://localhost:8081/oauth2/register -H 'Content-Type: application/json' -d '{
  "client_name": "my-agent",
  "redirect_uris": ["http://127.0.0.1:8765/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "scope": "mcp:tools mcp:resources"
}'
# -> 201 with a client_id (public client, PKCE); no client_secret
# (the same path on the internal :9000 also works)
```

Configuration notes (in `SecurityConfig`):

- **Open registration** (`openRegistrationAllowed(true)`) — the endpoint is **unauthenticated**, so
  any client can register. It is exposed on the public front door by default for MCP compliance (a
  generic client with no pre-configured `client_id` self-registers here); `work-mcp-gateway` gates it
  with `gateway.auth.dcr.exposed` (default `true` → proxied; `false` → 404 on `:8081`, still reachable
  on the internal `:9000`). **Keep it open in prod for an agent-native product — harden, don't disable.**
  Flood control is in place: the gateway applies a **per-IP rate limit** on `/oauth2/register`
  (`gateway.auth.dcr.rate-limit`; see `work-mcp-gateway`), and this server **reaps idle dynamic
  registrations** via `ExpiringRegisteredClientRepository` (`app.dcr.evict-unused-after`, default `1h`;
  a registration read in the meantime — authorize/token — stays alive; the seeded `demo-client`/
  `mcp-agent` are whitelisted and never evicted). Remaining hardening to add: a strict scope allowlist
  and loopback/https-only `redirect_uri`s. (Authenticated DCR via an RFC 7592 Initial Access Token or
  pre-registered clients are the options if you ever choose to *close* it — at the cost of self-onboarding.)
- **Zero egress during registration (enforced)** — the DCR validator chain (`DEFAULT_REDIRECT_URI_VALIDATOR`
  → a `jwks_uri` reject → `SIMPLE_SCOPE_VALIDATOR`) makes **no outbound calls** to client-supplied URLs:
  `jwks_uri` is rejected outright with `invalid_client_metadata` (the built-in `DEFAULT_JWK_SET_URI_VALIDATOR`
  only checked the scheme and never fetched; the reject makes "no by-reference client keys" an enforced
  invariant instead of an incidental one, so a future `private_key_jwt` client or a re-wired
  `X509SelfSignedCertificateVerifier` can't quietly open an SSRF/egress hole). OIDC is off so
  `sector_identifier_uri` is never read either. Open DCR is therefore safe behind a strict egress allowlist.
  By-value `jwks` would still be egress-safe if ever needed; public PKCE clients need no keys.
- **Self-declared scopes** — the default DCR validator rejects any `scope`; the SIMPLE scope validator
  is used so agents can declare `mcp:*` scopes (strict redirect-URI https/loopback + jwk checks are
  kept). Replace it with a custom validator to restrict agents to a fixed scope set.
- **Consent disabled** — headless agents have no consent UI, so the consent step is turned off for
  every client (dynamically-registered clients default to consent-required).
- Registrations are **in-memory and self-evicting** (`ExpiringRegisteredClientRepository`) — idle
  dynamic clients are reaped after `app.dcr.evict-unused-after` (default `1h`); the seeded static
  clients are whitelisted. Still lost on restart — swap in a persistent (JDBC)
  `RegisteredClientRepository` for production (Phase 4; that replaces the eviction repo and sets a real
  client-lifetime policy).

**Done — `work-mcp-gateway` now fronts this server:**

- **MCP resource-server side** — the gateway runs as the OAuth2 resource server: it validates these
  JWTs (issuer `http://localhost:8081` via `/oauth2/jwks`, enforces `aud = http://localhost:8081`),
  relays `sub` to the MCP backend as `X-Account-Id`, and serves **RFC 9728 Protected Resource Metadata**
  (`/.well-known/oauth-protected-resource`) listing this server under `authorization_servers`.

**Not yet done (next steps):**

- **Multiple resources** — `aud` is currently fixed to the single `app.mcp.resource`; extend the
  customizer to bind `aud` to the per-request `resource` when more than one MCP server exists.
- **Real SSO** — the gateway's account resolution is a dev `?account=` bypass; a signed SSO assertion
  / session-cookie flow (replacing the bypass) is the real integration still to build.
- **Persistent key/client store** — the in-memory RSA key and clients are recreated on each restart,
  so refresh tokens don't survive. Required before production.

## Extension points

- **Enable OIDC:** add `authorizationServer.oidc(Customizer.withDefaults())` in `SecurityConfig` and
  add the `openid` scope to the client.
- **Persist clients/users/keys:** swap the in-memory `RegisteredClientRepository`,
  `AccountService`, and `JWKSource` beans for database/persistent implementations. The in-memory RSA
  key is regenerated on each startup, so issued tokens don't survive a restart.
- **Consent page:** consent is globally disabled (headless agents have no UI) via the authorize
  provider's `setAuthorizationConsentRequired(...)` predicate, which overrides per-client settings.
  To require consent, remove that predicate and set `requireAuthorizationConsent(true)` on a client
  plus add a `/oauth2/consent` controller.
