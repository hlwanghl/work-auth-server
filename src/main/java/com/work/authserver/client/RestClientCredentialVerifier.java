package com.work.authserver.client;

import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.Map;
import java.util.Optional;

/**
 * The production {@link ClientCredentialVerifier}: POSTs {@code {clientId, clientSecret}} as JSON to
 * the configured registry endpoint (FR-16 in docs/requirements.md). A 2xx response whose body carries
 * an {@code accountId} means the credentials are valid; anything else — non-2xx, unparsable/absent
 * body, network error, timeout — is verification failure (never a partial trust).
 */
public class RestClientCredentialVerifier implements ClientCredentialVerifier {

    private final RestClient restClient;

    public RestClientCredentialVerifier(String url) {
        this.restClient = RestClient.builder().baseUrl(url).build();
    }

    @Override
    public Optional<VerifiedClient> verify(String clientId, String clientSecret) {
        try {
            VerifiedClient parsed = restClient.post()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("clientId", clientId, "clientSecret", clientSecret))
                    .retrieve()
                    .body(VerifiedClient.class);
            if (parsed == null || parsed.accountId() == null || parsed.accountId().isBlank()) {
                return Optional.empty();
            }
            // clientId is ours — we sent it; the API is not required to echo it.
            return Optional.of(new VerifiedClient(clientId, parsed.accountId()));
        } catch (RestClientException ex) {
            return Optional.empty();
        }
    }
}
