package com.work.authserver;

import com.work.authserver.config.AppProperties;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import tools.jackson.databind.JsonNode;

import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression-protects the hard-set issuer: the access token's {@code iss} must be the configured
 * public origin ({@code http://localhost:8081}, the gateway in front of this server), and its
 * {@code aud} must be the MCP resource &mdash; <em>not</em> this server's internal random test port.
 * The gateway validates tokens for exactly this issuer (it is the OAuth2 resource server; the MCP
 * server never sees the JWT).
 *
 * <p>This is the single most dangerous regression point in the "auth-server behind the gateway"
 * design, so it is asserted directly against the issued JWT claims.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TokenIssuerTests {

    @LocalServerPort
    private int port;

    @Autowired
    private AppProperties properties;

    private final HttpClient client = TestHttp.client();

    private String clientId;

    @BeforeAll
    void registerClient() throws Exception {
        this.clientId = TestHttp.registerPublicClient(client, port, TestHttp.REDIRECT_URI, "read");
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void accessTokenIssuerIsPublicOrigin() throws Exception {
        String verifier = "a-strong-random-verifier-value-with-43-to-128-chars-0123456789";
        String challenge = TestHttp.s256(verifier);

        // 1. Authorize as acct-123 (resolved from the header) -> consent -> redirect with code.
        String authorize = url("/oauth2/authorize?response_type=code&client_id=" + clientId
                + "&redirect_uri=" + URLEncoder.encode(TestHttp.REDIRECT_URI, StandardCharsets.UTF_8)
                + "&scope=read&state=xyz"
                + "&code_challenge=" + challenge
                + "&code_challenge_method=S256");
        HttpResponse<String> authorizeResponse = TestHttp.get(client, authorize, "X-Account-Id", "acct-123");
        HttpResponse<String> consent =
                TestHttp.approveConsent(client, url(""), authorizeResponse, "acct-123");
        assertThat(consent.statusCode()).isEqualTo(302);
        String code = TestHttp.parseQuery(consent.headers().firstValue("Location").orElseThrow()).get("code");
        assertThat(code).isNotBlank();

        // 2. Exchange code + verifier for tokens.
        Map<String, String> tokenParams = new LinkedHashMap<>();
        tokenParams.put("grant_type", "authorization_code");
        tokenParams.put("code", code);
        tokenParams.put("redirect_uri", TestHttp.REDIRECT_URI);
        tokenParams.put("client_id", clientId);
        tokenParams.put("code_verifier", verifier);
        HttpResponse<String> token = TestHttp.postForm(client, url("/oauth2/token"), tokenParams);
        assertThat(token.statusCode()).isEqualTo(200);

        // 3. iss must be the public origin (not this server's random port); aud must be the MCP resource.
        JsonNode claims = TestJwt.claims(token.body());
        assertThat(claims.get("iss").asString()).isEqualTo(properties.getIssuer());
        assertThat(claims.get("iss").asString()).isEqualTo("http://localhost:8081");
        assertThat(claims.get("iss").asString()).isNotEqualTo(url(""));
        JsonNode aud = claims.get("aud");
        String audience = aud.isArray() ? aud.get(0).asString() : aud.asString();
        assertThat(audience).isEqualTo(properties.getMcp().getResource());
    }
}
