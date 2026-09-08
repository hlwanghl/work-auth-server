package com.work.authserver.identity;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Resolves the current user from a trusted request header (default {@code X-Account-Id}), which a
 * gateway/proxy injects for already-authenticated users. If the header is present and the account
 * exists, the request is authenticated for this invocation. If the header is missing or the account
 * is unknown, no authentication is set and the request remains anonymous — the configured
 * {@link SsoRedirectAuthenticationEntryPoint} then redirects to the external SSO login.
 */
public class AccountIdHeaderAuthenticationFilter extends OncePerRequestFilter {

    private final AccountService accountService;
    private final String headerName;

    public AccountIdHeaderAuthenticationFilter(AccountService accountService, String headerName) {
        this.accountService = accountService;
        this.headerName = headerName;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            String accountId = request.getHeader(headerName);
            if (StringUtils.hasText(accountId)) {
                accountService.findByAccountId(accountId)
                        .ifPresent(this::authenticate);
            }
        }

        filterChain.doFilter(request, response);
    }

    private void authenticate(Account account) {
        SecurityContextHolder.getContext().setAuthentication(new AccountAuthentication(account));
    }
}
