package com.work.authserver.client;

import com.work.authserver.config.AppProperties;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Pins the pre-registered website-app shape (FR-15 in docs/requirements.md): a confidential client
 * with {@code client_secret_basic} auth (HTTP Basic only, per the latest OAuth 2.1 draft), PKCE
 * mandatory, consent mandatory, and the standard website grants (authorization_code + refresh_token —
 * no client_credentials: the secret authenticates the client redeeming a USER's code, see the
 * terminology note on FR-15).
 */
class PreRegisteredClientsTests {

    private AppProperties properties(AppProperties.WebApp... specs) {
        AppProperties properties = new AppProperties();
        properties.setWebClients(List.of(specs));
        return properties;
    }

    private AppProperties.WebApp demoSpec() {
        AppProperties.WebApp spec = new AppProperties.WebApp();
        spec.setClientId("web-app-demo");
        spec.setClientSecret("web-demo-secret");
        spec.setClientName("Demo Website App");
        spec.setRedirectUris(List.of("http://127.0.0.1:9090/callback"));
        spec.setScopes(List.of("profile"));
        return spec;
    }

    @Test
    void buildsConfidentialClientWithSecretPkceConsentAndAllGrants() {
        RegisteredClient client = PreRegisteredClients.from(properties(demoSpec())).get(0);

        assertThat(client.getClientId()).isEqualTo("web-app-demo");
        assertThat(client.getClientName()).isEqualTo("Demo Website App");
        // The {noop} prefix is required by the default DelegatingPasswordEncoder for verbatim secrets.
        assertThat(client.getClientSecret()).isEqualTo("{noop}web-demo-secret");
        assertThat(client.getClientAuthenticationMethods())
                .containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(client.getAuthorizationGrantTypes()).containsExactlyInAnyOrder(
                AuthorizationGrantType.AUTHORIZATION_CODE,
                AuthorizationGrantType.REFRESH_TOKEN);
        assertThat(client.getRedirectUris()).containsExactly("http://127.0.0.1:9090/callback");
        assertThat(client.getScopes()).containsExactly("profile");
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getClientSettings().isRequireAuthorizationConsent()).isTrue();
    }

    @Test
    void clientNameFallsBackToClientId() {
        AppProperties.WebApp spec = demoSpec();
        spec.setClientName(null);

        RegisteredClient client = PreRegisteredClients.from(properties(spec)).get(0);

        assertThat(client.getClientName()).isEqualTo("web-app-demo");
    }

    @Test
    void rejectsIncompleteSpec() {
        AppProperties.WebApp noSecret = demoSpec();
        noSecret.setClientSecret(" ");

        assertThatThrownBy(() -> PreRegisteredClients.from(properties(noSecret)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("web-app-demo");

        AppProperties.WebApp noRedirect = demoSpec();
        noRedirect.setRedirectUris(List.of());

        assertThatThrownBy(() -> PreRegisteredClients.from(properties(noRedirect)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void enabledRegistryStoresExternalMarkerAndNeedsNoConfiguredSecret() {
        AppProperties properties = properties(demoSpec());
        properties.getClientRegistry().setEnabled(true);
        // Even a blank configured secret is fine: the REST API owns the real secret (FR-16).
        properties.getWebClients().get(0).setClientSecret("");

        RegisteredClient client = PreRegisteredClients.from(properties).get(0);

        // The stored value carries only the client_id; the encoder delegates the check externally.
        assertThat(client.getClientSecret()).isEqualTo("{ext}web-app-demo");
    }
}
