package com.work.authserver;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.junit.jupiter.api.TestInstance;

import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Drives the full OAuth 2.1 Authorization Code + PKCE flow end-to-end over real HTTP, the way an MCP
 * client experiences it: DCR registration (no static clients, FR-6) -> authorize (with the
 * X-Account-Id header) -> explicit consent (FR-5) -> exchange code + verifier at the token endpoint ->
 * JWT access token. Also verifies the authorize endpoint redirects to the external SSO (preserving
 * the PKCE params in {@code return_to}) when no account-id header is present.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OAuth2PkceFlowTests {

    @LocalServerPort
    private int port;

    private final HttpClient client = TestHttp.client();

    private String clientId;

    @BeforeAll
    void registerClient() throws Exception {
        this.clientId = TestHttp.registerPublicClient(client, port, TestHttp.REDIRECT_URI, "read");
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private String authorizeUrl(String codeChallenge) {
        return url("/oauth2/authorize?response_type=code&client_id=" + clientId
                + "&redirect_uri=" + URLEncoder.encode(TestHttp.REDIRECT_URI, StandardCharsets.UTF_8)
                + "&scope=read&state=xyz"
                + "&code_challenge=" + codeChallenge
                + "&code_challenge_method=S256");
    }

    @Test
    void authorizeWithoutHeaderRedirectsToSso() throws Exception {
        HttpResponse<String> response = TestHttp.get(client, authorizeUrl("challenge-value"));

        assertThat(response.statusCode()).isEqualTo(302);
        String location = response.headers().firstValue("Location").orElseThrow();
        assertThat(location).startsWith("http://localhost:8081/dev-sso/login");
        assertThat(location).contains("return_to=");
        assertThat(location).contains("code_challenge");
    }

    @Test
    void authorizeWithTrailingSlashResourceIssuesCode() throws Exception {
        // RFC 8707 resource-indicator: a generic MCP client (the Inspector) normalizes the PRM resource
        // to add a root slash, sending resource=http://localhost:8081/ . That must be accepted as the
        // same resource as the configured http://localhost:8081 (RFC 3986: empty path == "/"), else the
        // client sees invalid_target and the OAuth dance dead-ends.
        String codeChallenge = TestHttp.s256("a-strong-random-verifier-value-with-43-to-128-chars-0123456789");
        String url = authorizeUrl(codeChallenge)
                + "&resource=" + URLEncoder.encode("http://localhost:8081/", StandardCharsets.UTF_8);

        HttpResponse<String> authorize = TestHttp.get(client, url, "X-Account-Id", "acct-123");
        HttpResponse<String> consent = TestHttp.approveConsent(client, url(""), authorize, "acct-123");

        assertThat(consent.statusCode()).isEqualTo(302);
        String location = consent.headers().firstValue("Location").orElseThrow();
        assertThat(location).startsWith(TestHttp.REDIRECT_URI);
        assertThat(location).contains("code=");
        assertThat(location).doesNotContain("invalid_target");
    }

    @Test
    void authorizationCodeWithPkce() throws Exception {
        String codeVerifier = "a-strong-random-verifier-value-with-43-to-128-chars-0123456789";
        String codeChallenge = TestHttp.s256(codeVerifier);

        // 1. Authorize as acct-123 (resolved from the header) -> consent page -> approve -> code
        HttpResponse<String> authorize =
                TestHttp.get(client, authorizeUrl(codeChallenge), "X-Account-Id", "acct-123");
        HttpResponse<String> consent =
                TestHttp.approveConsent(client, url(""), authorize, "acct-123");

        assertThat(consent.statusCode()).isEqualTo(302);
        String location = consent.headers().firstValue("Location").orElseThrow();
        String code = TestHttp.parseQuery(location).get("code");
        assertThat(code).isNotBlank();

        // 2. Exchange code + verifier for tokens
        Map<String, String> tokenParams = new LinkedHashMap<>();
        tokenParams.put("grant_type", "authorization_code");
        tokenParams.put("code", code);
        tokenParams.put("redirect_uri", TestHttp.REDIRECT_URI);
        tokenParams.put("client_id", clientId);
        tokenParams.put("code_verifier", codeVerifier);

        HttpResponse<String> token = TestHttp.postForm(client, url("/oauth2/token"), tokenParams);

        assertThat(token.statusCode()).isEqualTo(200);
        assertThat(token.body())
                .contains("\"access_token\"", "\"token_type\":\"Bearer\"", "\"scope\":\"read\"");
    }
}
