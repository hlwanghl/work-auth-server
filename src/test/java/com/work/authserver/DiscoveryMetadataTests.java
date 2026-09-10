package com.work.authserver;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.StringReader;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * FR-13 with minimal exposure: the RFC 8414 discovery document advertises exactly the enabled
 * capabilities — Spring Security hardcodes six client-authentication methods and four grant types
 * into the response (and omits {@code none}); discovery/DiscoveryMetadataPolicy trims the claims
 * down to the grants and auth methods the two client shapes use (FR-4/FR-7/FR-15).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class DiscoveryMetadataTests {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    @LocalServerPort
    private int port;

    private final HttpClient client = TestHttp.client();

    @Test
    void metadataAdvertisesOnlyEnabledCapabilities() throws Exception {
        HttpResponse<String> response = TestHttp.get(client,
                "http://localhost:" + port + "/.well-known/oauth-authorization-server");
        assertThat(response.statusCode()).isEqualTo(200);

        JsonNode metadata = MAPPER.readTree(new StringReader(response.body()));

        assertThat(claimValues(metadata, "grant_types_supported"))
                .containsExactly("authorization_code", "refresh_token");
        for (String claim : List.of("token_endpoint_auth_methods_supported",
                "revocation_endpoint_auth_methods_supported",
                "introspection_endpoint_auth_methods_supported")) {
            assertThat(claimValues(metadata, claim))
                    .as(claim)
                    .containsExactlyInAnyOrder("none", "client_secret_basic");
        }
        // Sanity: the trim narrows capability claims only — endpoint addresses stay published.
        assertThat(metadata.get("issuer")).isNotNull();
        assertThat(metadata.get("registration_endpoint")).isNotNull();
    }

    private static List<String> claimValues(JsonNode metadata, String claim) {
        List<String> values = new ArrayList<>();
        JsonNode array = metadata.get(claim);
        for (int i = 0; array != null && i < array.size(); i++) {
            values.add(array.get(i).asString());
        }
        return values;
    }
}
