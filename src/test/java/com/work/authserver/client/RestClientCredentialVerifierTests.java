package com.work.authserver.client;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The REST {@link ClientCredentialVerifier} against a real HTTP stub (FR-16 in docs/requirements.md):
 * a 2xx JSON body with an accountId verifies the client; any non-2xx, junk body or unreachable
 * endpoint is a verification failure (never partial trust).
 */
class RestClientCredentialVerifierTests {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    private static HttpServer server;
    private static int port;
    private static final AtomicReference<String> lastSeenSecret = new AtomicReference<>();

    @BeforeAll
    static void startStub() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        port = server.getAddress().getPort();
        server.createContext("/verify", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            JsonNode request = MAPPER.readTree(new StringReader(body));
            lastSeenSecret.set(request.get("clientSecret").asString());
            if (request.get("clientSecret").asString().equals("good-secret")) {
                byte[] response = "{\"accountId\":\"acct-777\",\"clientName\":\"Demo\"}"
                        .getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, response.length);
                exchange.getResponseBody().write(response);
            } else {
                exchange.sendResponseHeaders(401, -1);
            }
            exchange.close();
        });
        server.start();
    }

    @AfterAll
    static void stopStub() {
        server.stop(0);
    }

    private RestClientCredentialVerifier verifier() {
        return new RestClientCredentialVerifier("http://localhost:" + port + "/verify");
    }

    @Test
    void validCredentialsReturnVerifiedClientWithAccountId() {
        Optional<ClientCredentialVerifier.VerifiedClient> verified =
                verifier().verify("web-app", "good-secret");

        assertThat(verified).isPresent();
        assertThat(verified.get().clientId()).isEqualTo("web-app");
        assertThat(verified.get().accountId()).isEqualTo("acct-777");
        // Extra response fields (clientName) are ignored without breaking the parse.
        // The presented secret reached the API verbatim.
        assertThat(lastSeenSecret.get()).isEqualTo("good-secret");
    }

    @Test
    void invalidCredentialsReturnEmpty() {
        assertThat(verifier().verify("web-app", "bad-secret")).isEmpty();
    }

    @Test
    void unreachableEndpointReturnsEmpty() {
        // Port 1 is reserved and unbound: a network failure must be a verification failure.
        RestClientCredentialVerifier unreachable =
                new RestClientCredentialVerifier("http://localhost:1/verify");

        assertThat(unreachable.verify("web-app", "good-secret")).isEmpty();
    }
}
