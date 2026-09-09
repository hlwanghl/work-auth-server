package com.work.authserver.client;

import com.work.authserver.config.AppProperties;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.List;

/**
 * The pre-registered website apps (FR-15 in docs/requirements.md): confidential clients seeded from
 * {@code app.web-clients} configuration — registered ahead of time by the operator, NOT via open DCR
 * (which stays reserved for public MCP clients, FR-6/FR-7).
 *
 * <p>Built client shape: secret auth via HTTP Basic only ({@code client_secret_basic} — following the
 * latest OAuth 2.1 draft, which keeps Basic as the single password-based client authentication method),
 * PKCE mandatory (FR-4 — OAuth 2.1 recommends it for confidential clients too), explicit consent
 * mandatory (FR-5), and the OAuth 2.1 standard website grants: {@code authorization_code}
 * (+{@code refresh_token}). The secret authenticates the client when it redeems the user's code — the
 * issued tokens belong to the USER. The {@code client_credentials} grant (machine-to-machine, no user)
 * is intentionally NOT enabled: there is no consumer for it today (see the terminology note on FR-15
 * and docs/requirements.md §4). Secret verification is local in dev and delegated to the external
 * client registry when {@code app.client-registry.enabled=true} (FR-16).
 */
public final class PreRegisteredClients {

    private PreRegisteredClients() {
    }

    public static List<RegisteredClient> from(AppProperties properties) {
        return properties.getWebClients().stream()
                .map(spec -> toRegisteredClient(properties, spec))
                .toList();
    }

    /**
     * What is stored "as the secret" decides how the presented secret is checked (see
     * {@link ExternalClientSecretPasswordEncoder}): external-registry mode stores a marker carrying
     * only the client_id — the REST API owns the real secret (FR-16), so the configured
     * {@code client-secret} is not used at all; dev mode stores the configured secret verbatim.
     */
    private static String clientSecretStorage(AppProperties properties, AppProperties.WebApp spec) {
        return properties.getClientRegistry().isEnabled()
                ? ExternalClientSecretPasswordEncoder.EXTERNAL_PREFIX + spec.getClientId()
                : ExternalClientSecretPasswordEncoder.PLAIN_PREFIX + spec.getClientSecret();
    }

    private static RegisteredClient toRegisteredClient(AppProperties properties, AppProperties.WebApp spec) {
        boolean registryEnabled = properties.getClientRegistry().isEnabled();
        if (spec.getClientId() == null || spec.getClientId().isBlank()
                || spec.getRedirectUris() == null || spec.getRedirectUris().isEmpty()
                || (!registryEnabled && (spec.getClientSecret() == null || spec.getClientSecret().isBlank()))) {
            throw new IllegalStateException(
                    "app.web-clients entries need client-id, at least one redirect-uri and (unless "
                            + "app.client-registry.enabled) a client-secret"
                            + (spec.getClientId() == null ? "" : " (offending client-id: " + spec.getClientId() + ")"));
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(spec.getClientId())
                .clientId(spec.getClientId())
                .clientName(spec.getClientName() == null || spec.getClientName().isBlank()
                        ? spec.getClientId() : spec.getClientName())
                .clientSecret(clientSecretStorage(properties, spec))
                // HTTP Basic only (Authorization header) — the latest OAuth 2.1 draft keeps Basic as
                // the single password-based client authentication method.
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        spec.getRedirectUris().forEach(builder::redirectUri);
        spec.getScopes().forEach(builder::scope);
        return builder
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)             // PKCE mandatory for web apps too (FR-4/FR-15)
                        .requireAuthorizationConsent(true) // explicit approve/deny (FR-5)
                        .build())
                .build();
    }
}
