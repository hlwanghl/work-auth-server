package com.work.authserver;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises the RFC 8707 (resource indicator) overlay and MCP token audience over real HTTP, using a
 * dynamically-registered client (FR-6):
 * <ul>
 *   <li>issued access token's {@code aud} equals the configured MCP resource;</li>
 *   <li>an authorize request with the allowed {@code resource} succeeds (through the consent step);</li>
 *   <li>an authorize request with a disallowed {@code resource} is rejected with
 *       {@code invalid_target}.</li>
 * </ul>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class McpResourceIndicatorTests {

    private static final String AGENT_REDIRECT_URI = "http://127.0.0.1:8080/callback";

    @LocalServerPort
    private int port;

    @Autowired
    private com.work.authserver.config.AppProperties properties;

    private final HttpClient client = TestHttp.client();

    private String clientId;

    @BeforeAll
    void registerClient() throws Exception {
        this.clientId = TestHttp.registerPublicClient(client, port, AGENT_REDIRECT_URI, "mcp:tools");
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private String authorizeUrl(String resource, String codeChallenge) {
        String u = url("/oauth2/authorize?response_type=code&client_id=" + clientId
                + "&redirect_uri=" + URLEncoder.encode(AGENT_REDIRECT_URI, StandardCharsets.UTF_8)
                + "&scope=" + URLEncoder.encode("mcp:tools", StandardCharsets.UTF_8)
                + "&state=xyz"
                + "&code_challenge=" + codeChallenge
                + "&code_challenge_method=S256");
        if (resource != null) {
            u += "&resource=" + URLEncoder.encode(resource, StandardCharsets.UTF_8);
        }
        return u;
    }

    @Test
    void accessTokenAudienceIsMcpResource() throws Exception {
        String verifier = "a-strong-random-verifier-value-with-43-to-128-chars-0123456789";
        String challenge = TestHttp.s256(verifier);

        // 1. Authorize as acct-123 (no resource param) -> consent -> redirect with code
        HttpResponse<String> authorize =
                TestHttp.get(client, authorizeUrl(null, challenge), "X-Account-Id", "acct-123");
        HttpResponse<String> consent = TestHttp.approveConsent(client, url(""), authorize, "acct-123");
        assertThat(consent.statusCode()).isEqualTo(302);
        String code = TestHttp.parseQuery(consent.headers().firstValue("Location").orElseThrow()).get("code");
        assertThat(code).isNotBlank();

        // 2. Exchange code + verifier for tokens
        Map<String, String> tokenParams = new LinkedHashMap<>();
        tokenParams.put("grant_type", "authorization_code");
        tokenParams.put("code", code);
        tokenParams.put("redirect_uri", AGENT_REDIRECT_URI);
        tokenParams.put("client_id", clientId);
        tokenParams.put("code_verifier", verifier);

        HttpResponse<String> token = TestHttp.postForm(client, url("/oauth2/token"), tokenParams);
        assertThat(token.statusCode()).isEqualTo(200);

        // 3. The JWT access token's `aud` must be the MCP resource (RFC 8707 binding)
        assertThat(TestJwt.aud(token.body())).isEqualTo(properties.getMcp().getResource());
    }

    @Test
    void authorizeWithAllowedResourceSucceeds() throws Exception {
        HttpResponse<String> authorize = TestHttp.get(client,
                authorizeUrl(properties.getMcp().getResource(), "challenge-value"),
                "X-Account-Id", "acct-123");
        HttpResponse<String> consent = TestHttp.approveConsent(client, url(""), authorize, "acct-123");

        assertThat(consent.statusCode()).isEqualTo(302);
        assertThat(consent.headers().firstValue("Location").orElseThrow()).contains("code=");
    }

    @Test
    void authorizeWithDisallowedResourceIsRejected() throws Exception {
        HttpResponse<String> authorize = TestHttp.get(client,
                authorizeUrl("http://evil.example/mcp", "challenge-value"),
                "X-Account-Id", "acct-123");

        // The failure handler redirects the error back to the registered redirect_uri — before any
        // consent step (resource validation happens when the authorize request is converted).
        assertThat(authorize.statusCode()).isEqualTo(302);
        String location = authorize.headers().firstValue("Location").orElseThrow();
        assertThat(location).startsWith(AGENT_REDIRECT_URI);
        assertThat(location).contains("error=invalid_target");
    }
}
