package com.work.authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.work.authserver.client.ExpiringRegisteredClientRepository;
import com.work.authserver.mcp.McpAudienceTokenCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * Bean wiring for the authorization server: the client store, the token signing keys, the JWT
 * decoder, the hard-set issuer, and the MCP (RFC 8707) audience stamping. All policy logic lives in
 * the capability packages ({@code client/}, {@code mcp/}); this class only assembles beans.
 */
@Configuration
public class AuthorizationServerConfig {

    /**
     * The open-DCR client store: starts empty — this server ships NO static clients, every client is
     * an MCP client that self-registered (FR-6/FR-7) — in memory, with idle eviction (FR-9). Swap for
     * a persistent (JDBC) {@link RegisteredClientRepository} in production — registrations and
     * refresh tokens are lost on restart today (docs/architecture.md §9).
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(AppProperties properties) {
        return new ExpiringRegisteredClientRepository(properties.getDcr().getEvictUnusedAfter());
    }

    /**
     * Stamps the configured MCP resource identifier as the {@code aud} of every issued JWT access
     * token — the RFC 8707 binding the MCP resource server validates (FR-11).
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> mcpAudienceTokenCustomizer(AppProperties properties) {
        return new McpAudienceTokenCustomizer(properties.getMcp().getResource());
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
        // for exactly this issuer (FR-12).
        return AuthorizationServerSettings.builder()
                .issuer(properties.getIssuer())
                .build();
    }
}
