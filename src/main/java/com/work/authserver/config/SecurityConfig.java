package com.work.authserver.config;

import com.work.authserver.security.AccountIdHeaderAuthenticationFilter;
import com.work.authserver.security.McpResourceIndicatorAuthenticationConverter;
import com.work.authserver.security.SsoRedirectAuthenticationEntryPoint;
import com.work.authserver.user.AccountService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.util.List;
import java.util.function.Consumer;

/**
 * Two security filter chains:
 * <ol>
 *   <li><b>Order(1)</b> — the OAuth2 authorization-server protocol endpoints. The resource owner is
 *       resolved from the {@code X-Account-Id} header; when absent/unknown the browser is redirected
 *       to the external SSO. Pure OAuth 2.1 (OIDC disabled).</li>
 *   <li><b>Order(2)</b> — everything else (e.g. {@code /api/me}). Same header resolution and SSO
 *       redirect behaviour.</li>
 * </ol>
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AppProperties properties;
    private final AccountService accountService;
    private final AuthorizationServerSettings authorizationServerSettings;

    public SecurityConfig(AppProperties properties, AccountService accountService,
                          AuthorizationServerSettings authorizationServerSettings) {
        this.properties = properties;
        this.accountService = accountService;
        this.authorizationServerSettings = authorizationServerSettings;
    }

    private AccountIdHeaderAuthenticationFilter accountIdHeaderFilter() {
        return new AccountIdHeaderAuthenticationFilter(accountService, properties.getHeader().getName());
    }

    private SsoRedirectAuthenticationEntryPoint ssoEntryPoint() {
        return new SsoRedirectAuthenticationEntryPoint(
                properties.getSso().getLoginUrl(),
                properties.getSso().getReturnToParam());
    }

    /**
     * Disables the authorization-consent step for all clients (headless agents have no consent UI).
     */
    private static Consumer<List<AuthenticationProvider>> authorizationCodeAuthenticationProviders() {
        return providers -> providers.stream()
                .filter(OAuth2AuthorizationCodeRequestAuthenticationProvider.class::isInstance)
                .map(p -> (OAuth2AuthorizationCodeRequestAuthenticationProvider) p)
                .findFirst()
                .ifPresent(provider -> provider.setAuthorizationConsentRequired(context -> false));
    }

    /**
     * Lets a dynamically-registered client self-declare its scopes. The default DCR validator rejects
     * any scope ("scope must not be set during DCR"); this swaps in the SIMPLE scope validator while
     * keeping strict redirect-URI (https/loopback) validation and rejecting by-reference client keys
     * ({@code jwks_uri}) so the server never dereferences a client-supplied URL.
     */
    private static Consumer<List<AuthenticationProvider>> dcrAuthenticationProviders() {
        return providers -> {
            OAuth2ClientRegistrationAuthenticationProvider provider = providers.stream()
                    .filter(OAuth2ClientRegistrationAuthenticationProvider.class::isInstance)
                    .map(p -> (OAuth2ClientRegistrationAuthenticationProvider) p)
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException(
                            "OAuth2ClientRegistrationAuthenticationProvider not configured"));
            Consumer<OAuth2ClientRegistrationAuthenticationContext> validator =
                    OAuth2ClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
                            // Reject jwks_uri outright (replaces DEFAULT_JWK_SET_URI_VALIDATOR, which only
                            // checks the scheme). No by-reference client keys => the server has no client
                            // URL to dereference => no egress / SSRF surface during registration. See
                            // rejectByReferenceKeyUris().
                            .andThen(rejectByReferenceKeyUris())
                            .andThen(OAuth2ClientRegistrationAuthenticationValidator.SIMPLE_SCOPE_VALIDATOR);
            provider.setAuthenticationValidator(validator);
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

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerFilterChain(HttpSecurity http) throws Exception {
        http
                .oauth2AuthorizationServer(authorizationServer -> {
                    authorizationServer
                            // RFC 8707 resource-indicator overlay: validate the `resource` request
                            // parameter against the configured MCP resource (Spring AS 7.1 has no
                            // native RFC 8707 support). See McpResourceIndicatorAuthenticationConverter.
                            .authorizationEndpoint(endpoint -> endpoint
                                    .authorizationRequestConverter(
                                            new McpResourceIndicatorAuthenticationConverter(
                                                    List.of(properties.getMcp().getResource())))
                                    // Headless agents have no consent UI, so skip the consent step for
                                    // every client (dynamically-registered clients default to
                                    // consent-required otherwise). Static clients already disable it.
                                    .authenticationProviders(authorizationCodeAuthenticationProviders()))
                            // RFC 7591 Dynamic Client Registration with OPEN registration, so any agent
                            // (MCP client) can self-register a client_id at /oauth2/register. Open
                            // registration is unauthenticated and STAYS OPEN in prod for agent-native
                            // support (generic clients self-register); harden it — persistence + TTL/
                            // eviction, rate-limit, strict scope allowlist — rather than gating it off.
                            // Registered clients live in memory and are lost on restart (swap for a
                            // persistent repository before production).
                            .clientRegistrationEndpoint(clientRegistration -> clientRegistration
                                    .openRegistrationAllowed(true)
                                    // The default DCR validator rejects ANY scope ("scope must not be
                                    // set during DCR"). Agents self-declare their scopes, so use the
                                    // SIMPLE scope validator; jwks_uri is rejected (no by-reference client
                                    // keys -> no egress/SSRF surface), keeping strict redirect-URI
                                    // (https/loopback) validation.
                                    .authenticationProviders(dcrAuthenticationProviders()));
                    // Restrict this chain to the authorization-server protocol endpoints.
                    // OIDC is intentionally NOT enabled -> pure OAuth 2.1.
                    http.securityMatcher(authorizationServer.getEndpointsMatcher());
                })
                .authorizeHttpRequests(auth -> auth
                        // The DCR endpoint runs an open-registration flow (RFC 7591) with no client
                        // authentication, so it must be reachable anonymously. Its filter sits after
                        // AuthorizationFilter, hence the explicit permitAll.
                        .requestMatchers(authorizationServerSettings.getClientRegistrationEndpoint())
                        .permitAll()
                        .anyRequest().authenticated())
                // Identity is established per request from the X-Account-Id header (injected by the
                // gateway in front of this server), so no server-side session must be created or
                // reused — otherwise a principal set on one request could leak onto the next.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAfter(accountIdHeaderFilter(), SecurityContextHolderFilter.class)
                .exceptionHandling(exceptions -> exceptions
                        // Browser (text/html) requests to /oauth2/authorize that are unauthenticated
                        // are redirected to the external SSO; programmatic requests (e.g. the token
                        // endpoint) keep the default OAuth2 error entry point.
                        .defaultAuthenticationEntryPointFor(
                                ssoEntryPoint(),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAfter(accountIdHeaderFilter(), SecurityContextHolderFilter.class)
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(ssoEntryPoint()));

        return http.build();
    }
}
