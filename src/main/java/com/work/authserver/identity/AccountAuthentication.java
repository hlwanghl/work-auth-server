package com.work.authserver.identity;

import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * The resource owner resolved by {@link AccountIdHeaderAuthenticationFilter} for this request.
 * A dedicated type (rather than the generic {@code UsernamePasswordAuthenticationToken}, whose name
 * would misdescribe header-based resolution) so the identity mechanism is explicit. {@link #getName()}
 * — the account id, via {@link Account#getName()} — becomes the {@code sub} of issued tokens.
 */
public final class AccountAuthentication extends AbstractAuthenticationToken {

    private final Account account;

    public AccountAuthentication(Account account) {
        super(account.getAuthorities());
        this.account = account;
        setAuthenticated(true);
    }

    @Override
    public Object getPrincipal() {
        return account;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public String getName() {
        return account.getName();
    }
}
