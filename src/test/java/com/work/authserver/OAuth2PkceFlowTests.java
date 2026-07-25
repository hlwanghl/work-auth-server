package com.work.authserver;

import org.junit.jupiter.api.Test;
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
 * Drives the full OAuth 2.1 Authorization Code + PKCE flow end-to-end over real HTTP:
 * authorize (with the X-Account-Id header) -> exchange code + verifier at the token endpoint ->
 * JWT access token. Also verifies the authorize endpoint redirects to the external SSO (preserving
 * the PKCE params in {@code return_to}) when no account-id header is present.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OAuth2PkceFlowTests {

    @LocalServerPort
    private int port;

    private final HttpClient client = TestHttp.client();

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private String authorizeUrl(String codeChallenge) {
        return url("/oauth2/authorize?response_type=code&client_id=" + TestHttp.CLIENT_ID
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
    void authorizationCodeWithPkce() throws Exception {
        String codeVerifier = "a-strong-random-verifier-value-with-43-to-128-chars-0123456789";
        String codeChallenge = TestHttp.s256(codeVerifier);

        // 1. Authorize as acct-123 (resolved from the header) -> redirect to client with code
        HttpResponse<String> authorize =
                TestHttp.get(client, authorizeUrl(codeChallenge), "X-Account-Id", "acct-123");

        assertThat(authorize.statusCode()).isEqualTo(302);
        String location = authorize.headers().firstValue("Location").orElseThrow();
        String code = TestHttp.parseQuery(location).get("code");
        assertThat(code).isNotBlank();

        // 2. Exchange code + verifier for tokens
        Map<String, String> tokenParams = new LinkedHashMap<>();
        tokenParams.put("grant_type", "authorization_code");
        tokenParams.put("code", code);
        tokenParams.put("redirect_uri", TestHttp.REDIRECT_URI);
        tokenParams.put("client_id", TestHttp.CLIENT_ID);
        tokenParams.put("code_verifier", codeVerifier);

        HttpResponse<String> token = TestHttp.postForm(client, url("/oauth2/token"), tokenParams);

        assertThat(token.statusCode()).isEqualTo(200);
        assertThat(token.body())
                .contains("\"access_token\"", "\"token_type\":\"Bearer\"", "\"scope\":\"read\"");
    }
}
