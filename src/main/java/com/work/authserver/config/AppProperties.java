package com.work.authserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Application configuration for the header-based authentication model and the external SSO login.
 *
 * <pre>
 * app:
 *   issuer: http://localhost:8081
 *   header:
 *     name: X-Account-Id
 *   sso:
 *     login-url: https://sso.example.com/login
 *     return-to-param: return_to
 *   mcp:
 *     resource: http://localhost:8081
 *   dcr:
 *     evict-unused-after: 1h
 *   web-clients:
 *     - client-id: web-app-demo
 *       client-secret: ...
 *       redirect-uris: ["http://127.0.0.1:9090/callback"]
 *       scopes: [profile]
 * </pre>
 */
@ConfigurationProperties("app")
public class AppProperties {

    /**
     * The authorization server's issuer identifier &mdash; the {@code iss} claim stamped on every
     * issued token and the {@code issuer} advertised in {@code /.well-known/oauth-authorization-server}.
     *
     * <p>Hard-set (rather than derived from the request) so it is stable regardless of how the server
     * is reached. This server sits behind {@code work-mcp-gateway}, which is the public origin, so the
     * default is the gateway's URL ({@code http://localhost:8081}), not this server's internal
     * {@code :9000} port. The gateway validates tokens for exactly this issuer.
     */
    private String issuer = "http://localhost:8081";

    private Header header = new Header();
    private Sso sso = new Sso();
    private Mcp mcp = new Mcp();
    private Dcr dcr = new Dcr();
    private List<WebApp> webClients = new ArrayList<>();
    private ClientRegistry clientRegistry = new ClientRegistry();

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public Header getHeader() {
        return header;
    }

    public void setHeader(Header header) {
        this.header = header;
    }

    public Sso getSso() {
        return sso;
    }

    public void setSso(Sso sso) {
        this.sso = sso;
    }

    public Mcp getMcp() {
        return mcp;
    }

    public void setMcp(Mcp mcp) {
        this.mcp = mcp;
    }

    public Dcr getDcr() {
        return dcr;
    }

    public void setDcr(Dcr dcr) {
        this.dcr = dcr;
    }

    public List<WebApp> getWebClients() {
        return webClients;
    }

    public void setWebClients(List<WebApp> webClients) {
        this.webClients = webClients;
    }

    public ClientRegistry getClientRegistry() {
        return clientRegistry;
    }

    public void setClientRegistry(ClientRegistry clientRegistry) {
        this.clientRegistry = clientRegistry;
    }

    public static class Header {

        /** Name of the request header carrying the logged-in user's account id. */
        private String name = "X-Account-Id";

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }
    }

    public static class Sso {

        /** External login page to redirect to when the user is not authenticated. */
        private String loginUrl = "https://sso.example.com/login";

        /** Query parameter used to pass the URL the SSO should return the user to. */
        private String returnToParam = "return_to";

        public String getLoginUrl() {
            return loginUrl;
        }

        public void setLoginUrl(String loginUrl) {
            this.loginUrl = loginUrl;
        }

        public String getReturnToParam() {
            return returnToParam;
        }

        public void setReturnToParam(String returnToParam) {
            this.returnToParam = returnToParam;
        }
    }

    /**
     * MCP (Model Context Protocol) authorization settings.
     *
     * <p>MCP clients authorize against this server using OAuth 2.1 + PKCE and present the issued
     * token to a separate MCP server (an OAuth2 resource server). The {@code resource} value is:
     * <ul>
     *   <li>the {@code aud} (audience) stamped on every issued access token — RFC 8707 binds a
     *       token to a single resource, which the MCP server then validates; and</li>
     *   <li>the single allowed value of the {@code resource} request parameter (RFC 8707). A client
     *       requesting a different {@code resource} is rejected with {@code invalid_target}.</li>
     * </ul>
 * Note: Spring Authorization Server 7.1 has no native RFC 8707 support, so both behaviours are
 * implemented here as a thin overlay (see {@code mcp/ResourceIndicatorAuthenticationConverter}
 * and {@code mcp/McpAudienceTokenCustomizer}).
     */
    public static class Mcp {

        /**
         * The MCP server's resource identifier (typically its base URL). Becomes the access-token
         * {@code aud} and the sole allowed {@code resource} parameter. Leave blank to disable.
         */
        private String resource = "http://localhost:8081";

        public String getResource() {
            return resource;
        }

        public void setResource(String resource) {
            this.resource = resource;
        }
    }

    /**
     * Dynamic Client Registration (RFC 7591) housekeeping. Open DCR stays open in prod (agent-native),
     * so the client store self-cleans: idle dynamic registrations are reaped after
     * {@link #evictUnusedAfter}. Pre-registered website-app clients ({@code app.web-clients}) are
     * exempt — a low-traffic site must not be reaped for being idle. See
     * {@code client/ExpiringRegisteredClientRepository}.
     */
    public static class Dcr {

        /**
         * Idle dynamic registrations older than this are reaped by the scheduled sweep (a registration
         * that is read in the meantime &mdash; authorize/token &mdash; stays alive). Spring Boot binds
         * ISO-8601 ({@code PT1H}) or suffixed ({@code 1h}, {@code 3600s}) durations.
         */
        private Duration evictUnusedAfter = Duration.ofHours(1);

        public Duration getEvictUnusedAfter() {
            return evictUnusedAfter;
        }

        public void setEvictUnusedAfter(Duration evictUnusedAfter) {
            this.evictUnusedAfter = evictUnusedAfter;
        }
    }

    /**
     * External client-credential verification (FR-16 in docs/requirements.md). When enabled, a
     * website app's secret is NOT compared against the configured value: the (clientId, clientSecret)
     * pair is POSTed to the registry's URL and a 2xx response carrying an accountId means valid.
     * Any failure (non-2xx, missing accountId, network error) is an authentication failure.
     */
    public static class ClientRegistry {

        /** Whether secret verification is delegated to the external REST API (dev default: off). */
        private boolean enabled = false;

        /** The verification endpoint URL; required when {@link #enabled}. */
        private String url;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }
    }

    /**
     * A pre-registered website app (FR-15 in docs/requirements.md): a confidential client registered
     * ahead of time via configuration instead of open DCR. Sign-in runs the OAuth 2.1 standard
     * authorization code + PKCE + consent flow — the id+secret only authenticates the client when it
     * redeems the user's code (no client_credentials grant). Dev-grade: secrets live in config
     * verbatim — production needs an admin surface, hashed secrets and persistence
     * (docs/architecture.md §9), or external verification ({@code client-registry}), in which case
     * the configured secret is not used at all.
     */
    public static class WebApp {

        /** The pre-registered client_id. */
        private String clientId;

        /** The pre-registered client secret (used as-is by the in-memory store). */
        private String clientSecret;

        /** Human-readable name; defaults to the client_id. */
        private String clientName;

        /** Registered redirect URIs for the authorization-code flow. */
        private List<String> redirectUris = new ArrayList<>();

        /** Scopes this web app may request. */
        private List<String> scopes = new ArrayList<>();

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getClientName() {
            return clientName;
        }

        public void setClientName(String clientName) {
            this.clientName = clientName;
        }

        public List<String> getRedirectUris() {
            return redirectUris;
        }

        public void setRedirectUris(List<String> redirectUris) {
            this.redirectUris = redirectUris;
        }

        public List<String> getScopes() {
            return scopes;
        }

        public void setScopes(List<String> scopes) {
            this.scopes = scopes;
        }
    }
}
