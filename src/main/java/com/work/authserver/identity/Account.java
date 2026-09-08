package com.work.authserver.identity;

import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

/**
 * A resolved user account. Used directly as the security principal, so {@link #getName()} (the
 * account id) becomes the {@code sub} claim of issued access tokens.
 */
public class Account implements AuthenticatedPrincipal {

    private final String accountId;
    private final String username;
    private final Set<GrantedAuthority> authorities;

    public Account(String accountId, String username, Collection<? extends GrantedAuthority> authorities) {
        this.accountId = accountId;
        this.username = username;
        this.authorities = authorities == null ? Set.of() : Set.copyOf(authorities);
    }

    public String getAccountId() {
        return accountId;
    }

    /** Human-friendly display name (not used as the token subject). */
    public String getUsername() {
        return username;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.unmodifiableSet(authorities);
    }

    @Override
    public String getName() {
        return accountId;
    }
}
