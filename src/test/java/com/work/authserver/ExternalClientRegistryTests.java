package com.work.authserver;

import com.sun.net.httpserver.HttpServer;
import com.work.authserver.config.AppProperties;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * External client-credential verification (FR-16 in docs/requirements.md) end-to-end over real HTTP:
 * the auth server POSTs the presented (clientId, clientSecret) to a stubbed registry API and lets its
 * verdict decide — the secret configured in {@code app.web-clients} is ignored entirely, a rejection
 * is a plain invalid_client, and the user auth-code flow rides the same verification.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ExternalClientRegistryTests {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    /** The only secret the stubbed registry accepts. */
    private static final String REGISTRY_SECRET = "the-secret-only-the-registry-knows";

    private static HttpServer registry;
    private static int registryPort;
    private static final AtomicReference<String> lastVerifiedSecret = new AtomicReference<>();

    static {
        try {
            registry = HttpServer.create(new InetSocketAddress(0), 0);
            registryPort = registry.getAddress().getPort();
            registry.createContext("/verify", exchange -> {
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                JsonNode request = MAPPER.readTree(new StringReader(body));
                lastVerifiedSecret.set(request.get("clientSecret").asString());
                if (REGISTRY_SECRET.equals(request.get("clientSecret").asString())) {
                    byte[] response = "{\"accountId\":\"acct-555\",\"clientName\":\"Demo Website App\"}"
                            .getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, response.length);
                    exchange.getResponseBody().write(response);
                } else {
                    exchange.sendResponseHeaders(401, -1);
                }
                exchange.close();
            });
            registry.start();
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
    }

    @DynamicPropertySource
    static void registryProperties(DynamicPropertyRegistry properties) {
        properties.add("app.client-registry.enabled", () -> "true");
        properties.add("app.client-registry.url", () -> "http://localhost:" + registryPort + "/verify");
    }

    @LocalServerPort
    private int port;

    @Autowired
    private AppProperties properties;

    private final HttpClient client = TestHttp.client();

    private String webAppClientId;
    private String redirectUri;

    @BeforeAll
    void readPreRegisteredClient() {
        AppProperties.WebApp webApp = properties.getWebClients().get(0);
        this.webAppClientId = webApp.getClientId();
        this.redirectUri = webApp.getRedirectUris().get(0);
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    /** Runs authorize + consent approval as acct-123 and returns the authorization code. */
    private String authorizationCode() throws Exception {
        String verifier = "a-strong-random-verifier-value-with-43-to-128-chars-0123456789";
        String authorize = url("/oauth2/authorize?response_type=code&client_id=" + webAppClientId
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&scope=profile&state=xyz"
                + "&code_challenge=" + TestHttp.s256(verifier)
                + "&code_challenge_method=S256");
        HttpResponse<String> authorizeResponse =
                TestHttp.get(client, authorize, "X-Account-Id", "acct-123");
        HttpResponse<String> consent =
                TestHttp.approveConsent(client, url(""), authorizeResponse, "acct-123");
        assertThat(consent.statusCode()).isEqualTo(302);
        String code = TestHttp.parseQuery(consent.headers().firstValue("Location").orElseThrow()).get("code");
        assertThat(code).isNotBlank();
        return code;
    }

    private Map<String, String> tokenRequest(String code, String codeVerifier) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("grant_type", "authorization_code");
        params.put("code", code);
        params.put("redirect_uri", redirectUri);
        params.put("client_id", webAppClientId);
        params.put("code_verifier", codeVerifier);
        return params;
    }

    @Test
    void userSignInIsDecidedByTheExternalRegistry() throws Exception {
        String verifier = "a-strong-random-verifier-value-with-43-to-128-chars-0123456789";
        String code = authorizationCode();

        HttpResponse<String> token = TestHttp.postForm(client, url("/oauth2/token"),
                tokenRequest(code, verifier),
                "Authorization", TestHttp.basicAuth(webAppClientId, REGISTRY_SECRET));

        // Valid per the REGISTRY (not per application.yml — that secret is ignored in this mode).
        assertThat(token.statusCode()).isEqualTo(200);
        assertThat(TestJwt.claims(token.body()).get("sub").asString()).isEqualTo("acct-123");
        // The presented secret reached the registry verbatim.
        assertThat(lastVerifiedSecret.get()).isEqualTo(REGISTRY_SECRET);
    }

    @Test
    void rejectedByExternalRegistryMeansInvalidClient() throws Exception {
        String verifier = "a-strong-random-verifier-value-with-43-to-128-chars-0123456789";
        String code = authorizationCode();

        HttpResponse<String> token = TestHttp.postForm(client, url("/oauth2/token"),
                tokenRequest(code, verifier),
                "Authorization", TestHttp.basicAuth(webAppClientId, "web-demo-secret"));

        // "web-demo-secret" is the application.yml secret — irrelevant now; the registry said no.
        assertThat(token.statusCode()).isEqualTo(401);
        assertThat(token.body()).contains("invalid_client");
    }
}
