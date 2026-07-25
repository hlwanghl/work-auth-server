package com.work.authserver;

import com.work.authserver.config.AppProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.StringReader;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression-protects the hard-set issuer: the access token's {@code iss} must be the configured
 * public origin ({@code http://localhost:8081}, the gateway in front of this server), and its
 * {@code aud} must be the MCP resource &mdash; <em>not</em> this server's internal random test port.
 *
 * <p>This is the single most dangerous regression point in the "auth-server behind the gateway"
 * design, so it is asserted directly against the issued JWT claims.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TokenIssuerTests {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    @LocalServerPort
    private int port;

    @Autowired
    private AppProperties properties;

    private final HttpClient client = TestHttp.client();

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void accessTokenIssuerIsPublicOrigin() throws Exception {
        String verifier = "a-strong-random-verifier-value-with-43-to-128-chars-0123456789";
        String challenge = TestHttp.s256(verifier);

        // 1. Authorize as acct-123 (resolved from the header) -> redirect with code.
        String authorize = url("/oauth2/authorize?response_type=code&client_id=" + TestHttp.CLIENT_ID
                + "&redirect_uri=" + URLEncoder.encode(TestHttp.REDIRECT_URI, StandardCharsets.UTF_8)
                + "&scope=read&state=xyz"
                + "&code_challenge=" + challenge
                + "&code_challenge_method=S256");
        HttpResponse<String> authorizeResponse = TestHttp.get(client, authorize, "X-Account-Id", "acct-123");
        assertThat(authorizeResponse.statusCode()).isEqualTo(302);
        String code = TestHttp.parseQuery(authorizeResponse.headers().firstValue("Location").orElseThrow()).get("code");
        assertThat(code).isNotBlank();

        // 2. Exchange code + verifier for tokens.
        Map<String, String> tokenParams = new LinkedHashMap<>();
        tokenParams.put("grant_type", "authorization_code");
        tokenParams.put("code", code);
        tokenParams.put("redirect_uri", TestHttp.REDIRECT_URI);
        tokenParams.put("client_id", TestHttp.CLIENT_ID);
        tokenParams.put("code_verifier", verifier);
        HttpResponse<String> token = TestHttp.postForm(client, url("/oauth2/token"), tokenParams);
        assertThat(token.statusCode()).isEqualTo(200);

        // 3. iss must be the public origin (not this server's random port); aud must be the MCP resource.
        JsonNode claims = jwtClaims(token.body());
        assertThat(claims.get("iss").asString()).isEqualTo(properties.getIssuer());
        assertThat(claims.get("iss").asString()).isEqualTo("http://localhost:8081");
        assertThat(claims.get("iss").asString()).isNotEqualTo(url(""));
        JsonNode aud = claims.get("aud");
        String audience = aud.isArray() ? aud.get(0).asString() : aud.asString();
        assertThat(audience).isEqualTo(properties.getMcp().getResource());
    }

    /** Decodes the payload claims of the {@code access_token} in a token-endpoint response. */
    private static JsonNode jwtClaims(String tokenJson) throws Exception {
        String accessToken = MAPPER.readTree(new StringReader(tokenJson)).get("access_token").asString();
        String payload = accessToken.split("\\.")[1];
        String claimsJson = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);
        return MAPPER.readTree(new StringReader(claimsJson));
    }
}
