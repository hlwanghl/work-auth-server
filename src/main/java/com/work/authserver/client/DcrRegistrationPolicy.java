package com.work.authserver.client;

import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationValidator;

import java.util.List;
import java.util.function.Consumer;

/**
 * Validator chain for open Dynamic Client Registration (RFC 7591) — the security posture of
 * {@code /oauth2/register} in one place (FR-7/FR-8 in docs/requirements.md):
 *
 * <ol>
 *   <li>{@link OAuth2ClientRegistrationAuthenticationValidator#DEFAULT_REDIRECT_URI_VALIDATOR} —
 *       strict redirect-URI validation (https / loopback);</li>
 *   <li>{@link #rejectByReferenceKeyUris()} — {@code jwks_uri} rejected outright;</li>
 *   <li>{@link OAuth2ClientRegistrationAuthenticationValidator#SIMPLE_SCOPE_VALIDATOR} — clients may
 *       self-declare scopes (the default validator rejects any scope, which blocks the agent
 *       self-onboarding this server exists for).</li>
 * </ol>
 */
public final class DcrRegistrationPolicy {

    private DcrRegistrationPolicy() {
    }

    /** Consumer for the client-registration endpoint's {@code authenticationProviders(...)} wiring. */
    public static Consumer<List<AuthenticationProvider>> openRegistrationValidators() {
        return providers -> {
            OAuth2ClientRegistrationAuthenticationProvider provider = providers.stream()
                    .filter(OAuth2ClientRegistrationAuthenticationProvider.class::isInstance)
                    .map(p -> (OAuth2ClientRegistrationAuthenticationProvider) p)
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException(
                            "OAuth2ClientRegistrationAuthenticationProvider not configured"));
            provider.setAuthenticationValidator(
                    OAuth2ClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
                            .andThen(rejectByReferenceKeyUris())
                            .andThen(OAuth2ClientRegistrationAuthenticationValidator.SIMPLE_SCOPE_VALIDATOR));
        };
    }

    /**
     * Rejects {@code jwks_uri} (client keys by reference). Spring's {@code DEFAULT_JWK_SET_URI_VALIDATOR}
     * only checks the URL's scheme is {@code https} &mdash; it never fetches, so the server makes no
     * outbound call during registration today. But that no-egress posture is <em>incidental</em>: the
     * moment a confidential client (e.g. {@code private_key_jwt}) is ever introduced, the natural Spring
     * path dereferences a client-supplied {@code jwks_uri} &mdash; an SSRF / egress vector (a hostile
     * {@code jwks_uri} aimed at cloud-metadata {@code 169.254.169.254} or an internal host). Rejecting
     * by-reference keys at registration makes "we never fetch client URLs" an enforced invariant. By-value
     * keys ({@code jwks}) would still be egress-safe if ever needed; public PKCE clients
     * ({@code token_endpoint_auth_method=none}) need no keys at all.
     */
    private static Consumer<OAuth2ClientRegistrationAuthenticationContext> rejectByReferenceKeyUris() {
        return context -> {
            OAuth2ClientRegistration registration =
                    ((OAuth2ClientRegistrationAuthenticationToken) context.getAuthentication())
                            .getClientRegistration();
            if (registration.getJwkSetUrl() != null) {
                throw new OAuth2AuthenticationException(new OAuth2Error(
                        "invalid_client_metadata",
                        "jwks_uri is not accepted: this server does not dereference client-supplied URLs "
                                + "(SSRF / egress). Public PKCE clients need no keys.",
                        "https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2"));
            }
        };
    }
}
