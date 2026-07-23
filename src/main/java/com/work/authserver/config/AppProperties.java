package com.work.authserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Application configuration for the header-based authentication model and the external SSO login.
 *
 * <pre>
 * app:
 *   header:
 *     name: X-Account-Id
 *   sso:
 *     login-url: https://sso.example.com/login
 *     return-to-param: return_to
 *   mcp:
 *     resource: http://localhost:8081
 * </pre>
 */
@ConfigurationProperties("app")
public class AppProperties {

    private Header header = new Header();
    private Sso sso = new Sso();
    private Mcp mcp = new Mcp();

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
     * implemented here as a thin overlay (see {@code McpResourceIndicatorAuthenticationConverter}
     * and the access-token customizer in {@code AuthorizationServerConfig}).
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
}
