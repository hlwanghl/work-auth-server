package com.work.authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.work.authserver.client.ExpiringRegisteredClientRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

/**
 * Configures the registered OAuth2 client(s), the token signing keys, and the MCP (Model Context
 * Protocol) audience stamping.
 *
 * <p>This is a pure OAuth 2.1 setup: <em>public</em> clients using the authorization-code grant
 * with PKCE. {@link ClientAuthenticationMethod#NONE} means PKCE is mandatory (no client secret).
 * OIDC is intentionally not enabled — see {@code SecurityConfig}.
 *
 * <p>Two clients are registered:
 * <ul>
 *   <li>{@code demo-client} — generic demo of the auth-code + PKCE flow;</li>
 *   <li>{@code mcp-agent} — an AI agent (MCP client) that obtains tokens for the MCP server.</li>
 * </ul>
 */
@Configuration
public class AuthorizationServerConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository(AppProperties properties) {
        RegisteredClient demoClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-client")
                // Public client -> no secret, PKCE is automatically required
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/demo-client")
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scope("read")
                .scope("write")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true)
                        .build())
                .build();

        // AI agent (MCP client). Same public/PKCE model; MCP-relevant scopes; loopback callbacks
        // typical of a local agent. Adjust the redirect URIs to match your agent's callback.
        RegisteredClient mcpAgent = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("mcp-agent")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8080/callback")
                .redirectUri("http://localhost:3000/callback")
                .scope("mcp:tools")
                .scope("mcp:resources")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true)
                        .build())
                .build();

        return new ExpiringRegisteredClientRepository(List.of(demoClient, mcpAgent),
                properties.getDcr().getEvictUnusedAfter());
    }

    /**
     * Stamps the configured MCP resource identifier as the {@code aud} (audience) of every issued
     * JWT access token — the RFC 8707 resource binding the MCP server (resource server) validates.
     *
     * <p>Spring Authorization Server 7.1 has no native RFC 8707 support, so the audience is fixed
     * to the single configured {@code app.mcp.resource}. When multiple MCP resources are needed,
     * bind {@code aud} to the per-request {@code resource} parameter instead.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> mcpAudienceTokenCustomizer(AppProperties properties) {
        String resource = properties.getMcp().getResource();
        return context -> {
            if (resource == null || resource.isBlank()) {
                return;
            }
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getClaims().audience(List.of(resource));
            }
        };
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = new RSAKey.Builder(generateRsaKey())
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static RSAKey generateRsaKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .build();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(AppProperties properties) {
        // Issuer is hard-set to the public origin (work-mcp-gateway, :8081), not derived from the
        // request, so the `iss` claim and the authorization-server metadata are stable regardless of
        // how this server is reached (internal :9000 vs. proxied :8081). The gateway validates tokens
        // for exactly this issuer.
        return AuthorizationServerSettings.builder()
                .issuer(properties.getIssuer())
                .build();
    }
}
