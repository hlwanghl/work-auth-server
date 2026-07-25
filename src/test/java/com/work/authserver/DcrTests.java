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
 * RFC 7591 Dynamic Client Registration, end-to-end over real HTTP: an agent registers a public
 * (PKCE) client at {@code /oauth2/register} and then completes the full authorization-code + PKCE
 * flow (with the RFC 8707 {@code resource} parameter) using that dynamically-registered client.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class DcrTests {

    private static final String REDIRECT_URI = "http://127.0.0.1:8765/callback";
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
    void registerPublicClientThenAuthorizeAndExchangeToken() throws Exception {
        // 1. Register a public MCP client via RFC 7591 (open registration, no auth).
        String registration = """
                {
                  "client_name": "test-mcp-agent",
                  "redirect_uris": ["%s"],
                  "grant_types": ["authorization_code", "refresh_token"],
                  "response_types": ["code"],
                  "token_endpoint_auth_method": "none",
                  "scope": "mcp:tools mcp:resources"
                }
                """.formatted(REDIRECT_URI);

        HttpResponse<String> register = TestHttp.postJson(client, url("/oauth2/register"), registration);
        assertThat(register.statusCode()).isEqualTo(201);
        assertThat(register.body()).contains("\"token_endpoint_auth_method\":\"none\"");
        assertThat(register.body()).doesNotContain("client_secret");

        String clientId = jsonField(register.body(), "client_id");
        assertThat(clientId).isNotBlank();

        // 2. Authorize with the dynamic client (PKCE + the MCP resource param), as acct-123.
        String verifier = "a-strong-random-verifier-value-with-43-to-128-chars-0123456789";
        String challenge = TestHttp.s256(verifier);
        String authorize = url("/oauth2/authorize?response_type=code&client_id=" + clientId
                + "&redirect_uri=" + URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8)
                + "&scope=" + URLEncoder.encode("mcp:tools", StandardCharsets.UTF_8)
                + "&state=xyz"
                + "&code_challenge=" + challenge
                + "&code_challenge_method=S256"
                + "&resource=" + URLEncoder.encode(properties.getMcp().getResource(), StandardCharsets.UTF_8));
        HttpResponse<String> authorizeResponse =
                TestHttp.get(client, authorize, "X-Account-Id", "acct-123");
        assertThat(authorizeResponse.statusCode()).isEqualTo(302);
        String code = TestHttp.parseQuery(authorizeResponse.headers().firstValue("Location").orElseThrow()).get("code");
        assertThat(code).isNotBlank();

        // 3. Exchange the code + PKCE verifier for tokens.
        Map<String, String> tokenParams = new LinkedHashMap<>();
        tokenParams.put("grant_type", "authorization_code");
        tokenParams.put("code", code);
        tokenParams.put("redirect_uri", REDIRECT_URI);
        tokenParams.put("client_id", clientId);
        tokenParams.put("code_verifier", verifier);

        HttpResponse<String> token = TestHttp.postForm(client, url("/oauth2/token"), tokenParams);
        assertThat(token.statusCode()).isEqualTo(200);

        // 4. The token's audience is the MCP resource (RFC 8707), same as for static clients.
        assertThat(jwtAud(token.body())).isEqualTo(properties.getMcp().getResource());
    }

    private static String jsonField(String json, String field) throws Exception {
        JsonNode node = MAPPER.readTree(new StringReader(json)).get(field);
        return node == null ? null : node.asString();
    }

    @Test
    void byReferenceKeyJwksUriIsRejected() throws Exception {
        // jwks_uri (client keys by reference) must be rejected: the server must never dereference a
        // client-supplied URL (egress / SSRF surface). Use an https URL on purpose — the old
        // DEFAULT_JWK_SET_URI_VALIDATOR only checked the scheme and would have ACCEPTED this; rejecting it
        // proves the reject-validator is doing the work. A hostile jwks_uri aimed at cloud-metadata or an
        // internal host is the classic SSRF vector this guard blocks.
        String registration = """
                {
                  "client_name": "hostile-client",
                  "redirect_uris": ["%s"],
                  "grant_types": ["authorization_code"],
                  "response_types": ["code"],
                  "token_endpoint_auth_method": "none",
                  "jwks_uri": "https://attacker.example/.well-known/jwks.json"
                }
                """.formatted(REDIRECT_URI);

        HttpResponse<String> register = TestHttp.postJson(client, url("/oauth2/register"), registration);
        assertThat(register.statusCode()).isEqualTo(400);
        assertThat(register.body()).contains("invalid_client_metadata");
    }

    private static String jwtAud(String tokenJson) throws Exception {
        String accessToken = MAPPER.readTree(new StringReader(tokenJson)).get("access_token").asString();
        String payload = accessToken.split("\\.")[1];
        JsonNode claims = MAPPER.readTree(new StringReader(
                new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8)));
        JsonNode aud = claims.get("aud");
        return aud.isArray() ? aud.get(0).asString() : aud.asString();
    }
}
