package com.work.authserver.identity;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Redirects unauthenticated requests to an external SSO login URL, passing the originally-requested
 * URL (including query string, e.g. the full {@code /oauth2/authorize?…&code_challenge=…}) as a
 * {@code return_to} parameter so the SSO can send the user back to exactly where they were after a
 * successful login.
 *
 * <p>The target URL is derived solely from the incoming request, never from user input, so this
 * cannot be used as an open redirect.
 */
public class SsoRedirectAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final String loginUrl;
    private final String returnToParam;

    public SsoRedirectAuthenticationEntryPoint(String loginUrl, String returnToParam) {
        this.loginUrl = loginUrl;
        this.returnToParam = returnToParam;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException ex) {
        String targetUrl = request.getRequestURL().toString();
        String query = request.getQueryString();
        if (StringUtils.hasText(query)) {
            targetUrl = targetUrl + "?" + query;
        }

        String redirectUrl = UriComponentsBuilder.fromUriString(loginUrl)
                .queryParam(returnToParam, targetUrl)
                .build()
                .encode()
                .toUriString();

        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Location", redirectUrl);
    }
}
