package com.work.authserver.identity;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the SSO hand-off Location construction (FR-2/FR-3 in docs/requirements.md): a 302 to the
 * configured login URL with the originally-requested URL (including query string, e.g. the full
 * authorize request with its {@code code_challenge}) as a single-encoded {@code return_to} parameter.
 */
class SsoRedirectAuthenticationEntryPointTests {

    private static final String LOGIN_URL = "http://localhost:8081/dev-sso/login";

    private final SsoRedirectAuthenticationEntryPoint entryPoint =
            new SsoRedirectAuthenticationEntryPoint(LOGIN_URL, "return_to");

    @Test
    void redirectsToLoginUrlWithReturnTo() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        request.setQueryString("response_type=code&client_id=mcp-agent&code_challenge=abc");
        MockHttpServletResponse response = new MockHttpServletResponse();

        entryPoint.commence(request, response, null);

        assertThat(response.getStatus()).isEqualTo(302);
        String location = response.getHeader("Location");
        assertThat(location).startsWith(LOGIN_URL + "?return_to=");
        String returnTo = URLDecoder.decode(
                location.substring((LOGIN_URL + "?return_to=").length()), StandardCharsets.UTF_8);
        assertThat(returnTo).isEqualTo(
                "http://localhost/oauth2/authorize?response_type=code&client_id=mcp-agent&code_challenge=abc");
        // Single-encoded: one URLDecoder pass must already yield the plain URL.
        assertThat(returnTo).doesNotContain("%");
    }

    @Test
    void returnToWithoutQueryString() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/me");
        MockHttpServletResponse response = new MockHttpServletResponse();

        entryPoint.commence(request, response, null);

        String location = response.getHeader("Location");
        assertThat(location).startsWith(LOGIN_URL + "?return_to=");
        String returnTo = URLDecoder.decode(
                location.substring((LOGIN_URL + "?return_to=").length()), StandardCharsets.UTF_8);
        assertThat(returnTo).isEqualTo("http://localhost/api/me");
    }
}
