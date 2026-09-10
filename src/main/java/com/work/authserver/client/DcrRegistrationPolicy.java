package com.work.authserver.client;

import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationValidator;

import java.util.List;
import java.util.Set;
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
 *       self-onboarding this server exists for);</li>
 *   <li>{@link #publicPkceClientsOnly()} — open registration mints public PKCE clients only, so the
 *       capabilities the discovery document advertises (discovery/DiscoveryMetadataPolicy) are
 *       exactly the ones a dynamically registered client can hold.</li>
 * </ol>
 */
public final class DcrRegistrationPolicy {

    private static final Set<String> REGISTRABLE_GRANT_TYPES = Set.of(
            AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
            AuthorizationGrantType.REFRESH_TOKEN.getValue());

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
                            .andThen(OAuth2ClientRegistrationAuthenticationValidator.SIMPLE_SCOPE_VALIDATOR)
                            .andThen(publicPkceClientsOnly()));
        };
    }

    /**
     * Open registration is reserved for public PKCE clients (FR-7): {@code token_endpoint_auth_method}
     * must be {@code none} and {@code grant_types} (when present) a subset of auth code/refresh.
     * Without this, a registrant could mint a confidential client ({@code client_secret_basic} is
     * RFC 7591's default when the field is omitted — Spring generates a secret for it) or self-grant
     * an unadvertised grant such as {@code client_credentials}, and the server would silently serve
     * capabilities beyond its advertised surface. Pre-registered confidential clients (FR-15) do not
     * come in through this endpoint.
     */
    private static Consumer<OAuth2ClientRegistrationAuthenticationContext> publicPkceClientsOnly() {
        return context -> {
            OAuth2ClientRegistration registration =
                    ((OAuth2ClientRegistrationAuthenticationToken) context.getAuthentication())
                            .getClientRegistration();
            String authMethod = registration.getTokenEndpointAuthenticationMethod();
            List<String> grantTypes = registration.getGrantTypes();
            if (!ClientAuthenticationMethod.NONE.getValue().equals(authMethod)
                    || (grantTypes != null && (grantTypes.isEmpty()
                            || !REGISTRABLE_GRANT_TYPES.containsAll(grantTypes)))) {
                throw new OAuth2AuthenticationException(new OAuth2Error(
                        "invalid_client_metadata",
                        "open registration is for public PKCE clients only: token_endpoint_auth_method"
                                + " must be \"none\" and grant_types, when given, within"
                                + " [authorization_code, refresh_token]",
                        "https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2"));
            }
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
