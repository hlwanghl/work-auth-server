package com.work.authserver.mcp;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * Fast unit tests for the RFC 8707 resource-parameter validation (FR-10 in docs/requirements.md):
 * allowed / disallowed values, origin normalization (trailing slash), missing resource, and the
 * "no allowed resources configured -> validation disabled" mode.
 */
class ResourceIndicatorAuthenticationConverterTests {

    private static final String ALLOWED = "http://localhost:8081";

    @BeforeEach
    void setUpAuthorizationServerContext() {
        // The delegate authorize-request converter reads the AuthorizationServerContext (to detect a
        // pushed-authorization request); in production the AuthorizationServerContextFilter provides
        // it — in a bare unit test we must install one ourselves.
        AuthorizationServerContextHolder.setContext(new AuthorizationServerContext() {
            @Override
            public AuthorizationServerSettings getAuthorizationServerSettings() {
                return AuthorizationServerSettings.builder().build();
            }

            @Override
            public String getIssuer() {
                return getAuthorizationServerSettings().getIssuer();
            }
        });
    }

    @AfterEach
    void resetAuthorizationServerContext() {
        AuthorizationServerContextHolder.resetContext();
    }

    private ResourceIndicatorAuthenticationConverter converter(String... allowed) {
        return new ResourceIndicatorAuthenticationConverter(List.of(allowed));
    }

    private static MockHttpServletRequest authorizeRequest(String resource) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        // For GET requests OAuth2EndpointUtils only trusts parameters that literally appear in the
        // query string (anti parameter-pollution), so the mock needs both the parsed parameters and
        // a matching raw query string.
        String query = "response_type=code&client_id=mcp-agent"
                + "&redirect_uri=http://127.0.0.1:8080/callback&scope=mcp:tools&state=xyz"
                + "&code_challenge=challenge-value&code_challenge_method=S256";
        if (resource != null) {
            query += "&resource=" + resource;
        }
        request.setQueryString(query);
        request.setParameter("response_type", "code");
        request.setParameter("client_id", "mcp-agent");
        request.setParameter("redirect_uri", "http://127.0.0.1:8080/callback");
        request.setParameter("scope", "mcp:tools");
        request.setParameter("state", "xyz");
        request.setParameter("code_challenge", "challenge-value");
        request.setParameter("code_challenge_method", "S256");
        if (resource != null) {
            request.setParameter("resource", resource);
        }
        return request;
    }

    @Test
    void allowedResourceIsAccepted() {
        Authentication authentication = converter(ALLOWED).convert(authorizeRequest(ALLOWED));

        assertThat(authentication).isNotNull();
    }

    @Test
    void trailingSlashIsNormalizedToSameResource() {
        // RFC 3986: empty path == "/". Generic MCP clients (e.g. the Inspector) normalize the PRM
        // resource by adding the root slash; that must stay the same resource, not invalid_target.
        assertThat(converter(ALLOWED).convert(authorizeRequest(ALLOWED + "/"))).isNotNull();
        assertThat(converter(ALLOWED + "/").convert(authorizeRequest(ALLOWED))).isNotNull();
    }

    @Test
    void missingOrBlankResourceIsAllowed() {
        assertThat(converter(ALLOWED).convert(authorizeRequest(null))).isNotNull();
        assertThat(converter(ALLOWED).convert(authorizeRequest(" "))).isNotNull();
    }

    @Test
    void disallowedResourceIsRejectedWithInvalidTarget() {
        Throwable thrown = catchThrowable(() ->
                converter(ALLOWED).convert(authorizeRequest("http://evil.example/mcp")));

        assertThat(thrown).isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class);
        assertThat(((OAuth2AuthorizationCodeRequestAuthenticationException) thrown)
                .getError().getErrorCode()).isEqualTo("invalid_target");
    }

    @Test
    void emptyAllowedResourcesDisablesValidation() {
        assertThat(converter().convert(authorizeRequest("http://evil.example/mcp"))).isNotNull();
    }
}
