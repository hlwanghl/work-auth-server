package com.work.authserver.config;

import com.work.authserver.client.DcrRegistrationPolicy;
import com.work.authserver.discovery.DiscoveryMetadataPolicy;
import com.work.authserver.identity.AccountIdHeaderAuthenticationFilter;
import com.work.authserver.identity.AccountService;
import com.work.authserver.identity.SsoRedirectAuthenticationEntryPoint;
import com.work.authserver.mcp.ResourceIndicatorAuthenticationConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.util.List;

/**
 * The two security filter chains (the assembly point of every FR in docs/requirements.md — the
 * policy logic itself lives in the {@code identity/}, {@code client/} and {@code mcp/} packages):
 * <ol>
 *   <li><b>Order(1)</b> — the OAuth2 authorization-server protocol endpoints. The resource owner is
 *       resolved from the {@code X-Account-Id} header; when absent/unknown the browser is redirected
 *       to the external SSO. Pure OAuth 2.1 (OIDC disabled), RFC 8707 resource validation and a
 *       mandatory consent step on the authorize endpoint, open RFC 7591 DCR.</li>
 *   <li><b>Order(2)</b> — everything else (e.g. {@code /api/me}, {@code /error}). Same header
 *       resolution and SSO redirect behaviour.</li>
 * </ol>
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AppProperties properties;
    private final AccountService accountService;
    private final AuthorizationServerSettings authorizationServerSettings;
    private final PasswordEncoder clientSecretPasswordEncoder;

    public SecurityConfig(AppProperties properties, AccountService accountService,
                          AuthorizationServerSettings authorizationServerSettings,
                          PasswordEncoder clientSecretPasswordEncoder) {
        this.properties = properties;
        this.accountService = accountService;
        this.authorizationServerSettings = authorizationServerSettings;
        this.clientSecretPasswordEncoder = clientSecretPasswordEncoder;
    }

    private AccountIdHeaderAuthenticationFilter accountIdHeaderFilter() {
        return new AccountIdHeaderAuthenticationFilter(accountService, properties.getHeader().getName());
    }

    private SsoRedirectAuthenticationEntryPoint ssoEntryPoint() {
        return new SsoRedirectAuthenticationEntryPoint(
                properties.getSso().getLoginUrl(),
                properties.getSso().getReturnToParam());
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerFilterChain(HttpSecurity http) throws Exception {
        http
                .oauth2AuthorizationServer(authorizationServer -> {
                    authorizationServer
                            // RFC 8707 resource-indicator overlay: validate the `resource` request
                            // parameter against the configured MCP resource (Spring AS 7.1 has no
                            // native RFC 8707 support). See mcp/ResourceIndicatorAuthenticationConverter.
                            .authorizationEndpoint(endpoint -> endpoint
                                    .authorizationRequestConverter(
                                            new ResourceIndicatorAuthenticationConverter(
                                                    List.of(properties.getMcp().getResource())))
                                    // Consent is mandatory (FR-5): every client is dynamically registered
                                    // and the DCR provider builds clients with
                                    // requireAuthorizationConsent=true, so the authorize endpoint must
                                    // know where to render the consent page. The consent submission
                                    // (POST /oauth2/authorize with client_id+state+scope) is handled by
                                    // Spring AS's built-in consent converter/provider; the page itself
                                    // is web/ConsentController (on the default chain, so an
                                    // unauthenticated user is bounced to the SSO first).
                                    .consentPage("/oauth2/consent"))
                            // RFC 7591 Dynamic Client Registration with OPEN registration, so any agent
                            // (MCP client) can self-register a client_id at /oauth2/register. Open
                            // registration is unauthenticated and STAYS OPEN in prod for agent-native
                            // support (generic clients self-register); harden it — persistence + TTL/
                            // eviction, rate-limit, strict scope allowlist — rather than gating it off.
                            // The validator chain (https/loopback redirect URIs, jwks_uri rejected,
                            // self-declared scopes) is client/DcrRegistrationPolicy.
                            .clientRegistrationEndpoint(clientRegistration -> clientRegistration
                                    .openRegistrationAllowed(true)
                                    .authenticationProviders(DcrRegistrationPolicy.openRegistrationValidators()))
                            // RFC 8414 metadata discloses only the enabled capabilities (FR-13,
                            // minimal exposure): Spring Security hardcodes six client-auth methods
                            // and four grant types into the discovery document; trim them to the
                            // grants/auth methods the two client shapes use (discovery/
                            // DiscoveryMetadataPolicy — DCR enforces the same set, see above).
                            .authorizationServerMetadataEndpoint(metadata -> metadata
                                    .authorizationServerMetadataCustomizer(
                                            DiscoveryMetadataPolicy.advertiseOnlyEnabledCapabilities()))
                            // Client-secret verification (FR-16): swap the PasswordEncoder of the
                            // built-in provider — stored secrets are {noop}<secret> (dev, verbatim
                            // compare) or {ext}<clientId> (external registry REST API decides).
                            .clientAuthentication(clientAuthentication -> clientAuthentication
                                    .authenticationProviders(providers -> providers.stream()
                                            .filter(ClientSecretAuthenticationProvider.class::isInstance)
                                            .map(ClientSecretAuthenticationProvider.class::cast)
                                            .findFirst()
                                            .ifPresent(provider -> provider
                                                    .setPasswordEncoder(clientSecretPasswordEncoder))));
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
                        // are redirected to the external SSO. The entry point is scoped to that path:
                        // it is the only user-facing endpoint on this chain — every other protocol
                        // endpoint (token, introspect, revoke) is client-authenticated and must keep
                        // the protocol error semantics (e.g. 401 invalid_client), not redirect to a
                        // login page. Programmatic requests to authorize keep the default entry point.
                        .defaultAuthenticationEntryPointFor(
                                ssoEntryPoint(),
                                new AndRequestMatcher(
                                        PathPatternRequestMatcher.withDefaults().matcher("/oauth2/authorize"),
                                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML))));

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        // Spring Boot's global error path: if an unrecoverable authorize error
                        // cascades here via BasicErrorController, render it instead of redirecting
                        // to the SSO (which, behind the gateway, surfaces as a 404). Belt-and-
                        // suspenders to the /oauth2/error permitAll on the authorization-server
                        // chain, which is the preferred render target.
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAfter(accountIdHeaderFilter(), SecurityContextHolderFilter.class)
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(ssoEntryPoint()));

        return http.build();
    }
}
