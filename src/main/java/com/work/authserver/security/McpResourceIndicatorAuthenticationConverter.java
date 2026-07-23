package com.work.authserver.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Validates the RFC 8707 {@code resource} parameter on the authorization request.
 *
 * <p>Spring Authorization Server 7.1 has no native RFC 8707 support, so this converter wraps the
 * default authorize-request converter and rejects a {@code resource} value that is not one of the
 * allowed resources (the configured MCP resource), throwing {@code invalid_target}. A missing
 * {@code resource} is allowed (some clients omit it); the token's {@code aud} is stamped regardless
 * — see {@code AuthorizationServerConfig#mcpAudienceTokenCustomizer}.
 *
 * <p>Thrown errors are handled by the authorization-server failure handler, which redirects the
 * error back to the client's {@code redirect_uri} (when valid) as {@code error=invalid_target}.
 */
public class McpResourceIndicatorAuthenticationConverter implements AuthenticationConverter {

    private final AuthenticationConverter delegate =
            new OAuth2AuthorizationCodeRequestAuthenticationConverter();
    private final Set<String> allowedResources;

    public McpResourceIndicatorAuthenticationConverter(Collection<String> allowedResources) {
        this.allowedResources = new HashSet<>();
        if (allowedResources != null) {
            for (String resource : allowedResources) {
                if (resource != null && !resource.isBlank()) {
                    this.allowedResources.add(resource);
                }
            }
        }
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        Authentication authentication = delegate.convert(request);
        if (authentication == null) {
            return null;
        }
        // No allowed resources configured -> RFC 8707 validation disabled.
        if (allowedResources.isEmpty()) {
            return authentication;
        }
        String resource = request.getParameter("resource");
        if (resource != null && !resource.isBlank() && !allowedResources.contains(resource)) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    new OAuth2Error("invalid_target", "Invalid resource parameter: " + resource, null),
                    (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication);
        }
        return authentication;
    }
}
