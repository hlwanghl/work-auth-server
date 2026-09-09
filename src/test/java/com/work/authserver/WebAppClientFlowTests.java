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
 * Website-app integration (FR-15 in docs/requirements.md), end-to-end over real HTTP with the
 * pre-registered confidential client from {@code app.web-clients}: user sign-in = authorization code
 * + PKCE (mandatory even for confidential clients) + explicit consent; the token exchange is
 * authenticated with the client secret (HTTP Basic) and yields access + refresh tokens for the USER.
 * The secret only authenticates the client redeeming the code — there is no client_credentials grant.
 * <ul>
 *   <li>the token endpoint rejects a wrong secret.</li>
 * </ul>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WebAppClientFlowTests {

    @LocalServerPort
    private int port;

    @Autowired
    private AppProperties properties;

    private final HttpClient client = TestHttp.client();

    private AppProperties.WebApp webApp;

    @BeforeAll
    void readPreRegisteredClient() {
        this.webApp = properties.getWebClients().get(0);
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private String redirectUri() {
        return webApp.getRedirectUris().get(0);
    }

    private String authorizeUrl(String codeChallenge) {
        return url("/oauth2/authorize?response_type=code&client_id=" + webApp.getClientId()
                + "&redirect_uri=" + URLEncoder.encode(redirectUri(), StandardCharsets.UTF_8)
                + "&scope=" + URLEncoder.encode(webApp.getScopes().get(0), StandardCharsets.UTF_8)
                + "&state=xyz"
                + "&code_challenge=" + codeChallenge
                + "&code_challenge_method=S256");
    }

    /** Runs authorize + consent approval for acct-123 and returns the authorization code. */
    private String authorizationCode(String codeChallenge) throws Exception {
        HttpResponse<String> authorize =
                TestHttp.get(client, authorizeUrl(codeChallenge), "X-Account-Id", "acct-123");
        HttpResponse<String> consent =
                TestHttp.approveConsent(client, url(""), authorize, "acct-123");
        assertThat(consent.statusCode()).isEqualTo(302);
        String location = consent.headers().firstValue("Location").orElseThrow();
        assertThat(location).startsWith(redirectUri());
        String code = TestHttp.parseQuery(location).get("code");
        assertThat(code).isNotBlank();
        return code;
    }

    /** Token request form for the authorization-code grant; the secret rides in the Basic header. */
    private Map<String, String> tokenRequest(String code, String codeVerifier) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("grant_type", "authorization_code");
        if (code != null) {
            params.put("code", code);
        }
        params.put("redirect_uri", redirectUri());
        params.put("client_id", webApp.getClientId());
        if (codeVerifier != null) {
            params.put("code_verifier", codeVerifier);
        }
        return params;
    }

    @Test
    void userSignInWithSecretPkceAndConsentIssuesAccessAndRefreshTokens() throws Exception {
        String verifier = "a-strong-random-verifier-value-with-43-to-128-chars-0123456789";
        String code = authorizationCode(TestHttp.s256(verifier));

        HttpResponse<String> token = TestHttp.postForm(client, url("/oauth2/token"),
                tokenRequest(code, verifier),
                "Authorization", TestHttp.basicAuth(webApp.getClientId(), webApp.getClientSecret()));

        assertThat(token.statusCode()).isEqualTo(200);
        assertThat(token.body()).contains("\"refresh_token\"");
        JsonNode claims = TestJwt.claims(token.body());
        assertThat(claims.get("sub").asString()).isEqualTo("acct-123");
        assertThat(TestJwt.aud(token.body())).isEqualTo(properties.getMcp().getResource());
    }

    @Test
    void tokenEndpointRejectsWrongClientSecret() throws Exception {
        String verifier = "a-strong-random-verifier-value-with-43-to-128-chars-0123456789";
        String code = authorizationCode(TestHttp.s256(verifier));

        HttpResponse<String> token = TestHttp.postForm(client, url("/oauth2/token"),
                tokenRequest(code, verifier),
                "Authorization", TestHttp.basicAuth(webApp.getClientId(), "wrong-secret"));

        assertThat(token.statusCode()).isEqualTo(401);
        assertThat(token.body()).contains("invalid_client");
    }

    @Test
    void pkceIsRequiredForConfidentialClientsToo() throws Exception {
        String verifier = "a-strong-random-verifier-value-with-43-to-128-chars-0123456789";
        String code = authorizationCode(TestHttp.s256(verifier));

        // Correct secret but no code_verifier — PKCE is mandatory (FR-4), the code must not redeem.
        HttpResponse<String> token = TestHttp.postForm(client, url("/oauth2/token"),
                tokenRequest(code, null),
                "Authorization", TestHttp.basicAuth(webApp.getClientId(), webApp.getClientSecret()));

        assertThat(token.statusCode()).isEqualTo(400);
        assertThat(token.body()).contains("invalid_grant");
    }
}
