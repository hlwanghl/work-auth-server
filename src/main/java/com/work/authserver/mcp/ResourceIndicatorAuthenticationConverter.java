package com.work.authserver.mcp;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.net.URI;
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
 * — see {@link McpAudienceTokenCustomizer}.
 *
 * <p>Comparison is <b>origin-normalized</b>: {@code http://host:port} and {@code http://host:port/} are
 * the same resource (RFC 3986 — an empty path equals {@code /}), so a generic client that normalizes
 * the PRM {@code resource} to add the root slash (e.g. the MCP Inspector) is not rejected.
 *
 * <p>Thrown errors are handled by the authorization-server failure handler, which redirects the
 * error back to the client's {@code redirect_uri} (when valid) as {@code error=invalid_target}.
 */
public class ResourceIndicatorAuthenticationConverter implements AuthenticationConverter {

    private final AuthenticationConverter delegate =
            new OAuth2AuthorizationCodeRequestAuthenticationConverter();
    private final Set<String> allowedResources;

    public ResourceIndicatorAuthenticationConverter(Collection<String> allowedResources) {
        this.allowedResources = new HashSet<>();
        if (allowedResources != null) {
            for (String resource : allowedResources) {
                if (resource != null && !resource.isBlank()) {
                    this.allowedResources.add(normalize(resource));
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
        if (resource != null && !resource.isBlank() && !allowedResources.contains(normalize(resource))) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    new OAuth2Error("invalid_target", "Invalid resource parameter: " + resource, null),
                    (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication);
        }
        return authentication;
    }

    /**
     * Canonicalizes a resource URL so origin strings compare equal regardless of a trailing slash:
     * {@code http://host:port} and {@code http://host:port/} denote the same resource (RFC 3986 treats
     * an empty path as equivalent to {@code /}). Generic MCP clients (e.g. the MCP Inspector) normalize
     * the PRM {@code resource} to add the root slash; a verbatim {@code Set.contains} would then reject
     * a legitimate value with {@code invalid_target}. A non-absolute or unparseable value is compared
     * verbatim (trimmed) as a fallback.
     */
    private static String normalize(String resource) {
        if (resource == null || resource.isBlank()) {
            return "";
        }
        String trimmed = resource.trim();
        try {
            URI uri = URI.create(trimmed).normalize();
            if (uri.getScheme() == null || uri.getHost() == null) {
                return trimmed;
            }
            String path = uri.getPath();
            if (path == null || path.isEmpty()) {
                // Re-add the root path so http://host:port == http://host:port/.
                return new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), "/", null, null)
                        .toString();
            }
            return uri.toString();
        } catch (Exception e) {
            return trimmed;
        }
    }
}
