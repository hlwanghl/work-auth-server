package com.work.authserver.mcp;

import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.List;

/**
 * Stamps the configured MCP resource identifier as the {@code aud} (audience) of every issued JWT
 * access token — the RFC 8707 resource binding the MCP server (resource server) validates.
 *
 * <p>Spring Authorization Server 7.1 has no native RFC 8707 support, so the audience is fixed to the
 * single configured {@code app.mcp.resource}. When multiple MCP resources are needed, bind {@code aud}
 * to the per-request {@code resource} parameter instead (see docs/architecture.md §9).
 */
public final class McpAudienceTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final String resource;

    public McpAudienceTokenCustomizer(String resource) {
        this.resource = resource;
    }

    @Override
    public void customize(JwtEncodingContext context) {
        if (resource == null || resource.isBlank()) {
            return;
        }
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            context.getClaims().audience(List.of(resource));
        }
    }
}
