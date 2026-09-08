package com.work.authserver;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The consent step (FR-5 in docs/requirements.md) over real HTTP: an authorization request from a
 * dynamically-registered client (which is built with {@code requireAuthorizationConsent=true}) must
 * detour through the consent page, the page itself requires a logged-in user, renders the requested
 * scopes, and only the explicit approval issues the code.
 *
 * <p>Approvals are recorded per user + client and persist for the life of the server, so every test
 * registers its own fresh client.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ConsentFlowTests {

    @LocalServerPort
    private int port;

    private final HttpClient client = TestHttp.client();

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private String authorizeUrl(String clientId) {
        return url("/oauth2/authorize?response_type=code&client_id=" + clientId
                + "&redirect_uri=" + URLEncoder.encode(TestHttp.REDIRECT_URI, StandardCharsets.UTF_8)
                + "&scope=read&state=xyz"
                + "&code_challenge=challenge-value"
                + "&code_challenge_method=S256");
    }

    @Test
    void authorizeRedirectsToConsentPage() throws Exception {
        String clientId = TestHttp.registerPublicClient(client, port, TestHttp.REDIRECT_URI, "read");

        HttpResponse<String> authorize = TestHttp.get(client, authorizeUrl(clientId), "X-Account-Id", "acct-123");

        assertThat(authorize.statusCode()).isEqualTo(302);
        String location = authorize.headers().firstValue("Location").orElseThrow();
        assertThat(location).contains("/oauth2/consent?");
        assertThat(location).contains("client_id=" + clientId);
        assertThat(location).contains("scope=read");
        assertThat(location).contains("state=");
    }

    @Test
    void unauthenticatedConsentPageRedirectsToSso() throws Exception {
        // A user must be logged in to consent: the consent page sits on the default chain behind the
        // header filter, so without the account header it behaves like any other page (SSO redirect).
        String clientId = TestHttp.registerPublicClient(client, port, TestHttp.REDIRECT_URI, "read");
        HttpResponse<String> response = TestHttp.get(client,
                url("/oauth2/consent?client_id=" + clientId + "&scope=read&state=consent-state"));

        assertThat(response.statusCode()).isEqualTo(302);
        String location = response.headers().firstValue("Location").orElseThrow();
        assertThat(location).startsWith("http://localhost:8081/dev-sso/login");
        assertThat(location).contains("return_to=");
        assertThat(location).contains("/oauth2/consent");
    }

    @Test
    void consentPageRendersScopesAndApprovalForm() throws Exception {
        String clientId = TestHttp.registerPublicClient(client, port, TestHttp.REDIRECT_URI, "read");
        HttpResponse<String> authorize = TestHttp.get(client, authorizeUrl(clientId), "X-Account-Id", "acct-123");
        String consentLocation = authorize.headers().firstValue("Location").orElseThrow();

        // The consent redirect is an absolute URL; fetch the page as the logged-in user would.
        HttpResponse<String> page = TestHttp.get(client, consentLocation, "X-Account-Id", "acct-123");

        assertThat(page.statusCode()).isEqualTo(200);
        String html = page.body();
        // The form contract Spring AS's consent provider consumes:
        assertThat(html).contains("action=\"/oauth2/authorize\"");
        assertThat(html).contains("name=\"client_id\" value=\"" + clientId + "\"");
        String state = TestHttp.parseQueryValues(consentLocation, "state").get(0);
        assertThat(html).contains("name=\"state\" value=\"" + state + "\"");
        assertThat(html).contains("name=\"scope\" value=\"read\" checked");
        assertThat(html).contains("同意");
        assertThat(html).contains("拒绝");
        // The resource owner shown is the account resolved from the header.
        assertThat(html).contains("alice");
    }

    @Test
    void approvingConsentIssuesCode() throws Exception {
        String clientId = TestHttp.registerPublicClient(client, port, TestHttp.REDIRECT_URI, "read");

        HttpResponse<String> authorize = TestHttp.get(client, authorizeUrl(clientId), "X-Account-Id", "acct-123");
        HttpResponse<String> consent = TestHttp.approveConsent(client, url(""), authorize, "acct-123");

        assertThat(consent.statusCode()).isEqualTo(302);
        String location = consent.headers().firstValue("Location").orElseThrow();
        assertThat(location).startsWith(TestHttp.REDIRECT_URI);
        assertThat(location).contains("code=");
        // The client's original state passes through to the authorization response.
        assertThat(TestHttp.parseQuery(location).get("state")).isEqualTo("xyz");
    }

    @Test
    void denyingConsentSendsAccessDeniedBackToClient() throws Exception {
        String clientId = TestHttp.registerPublicClient(client, port, TestHttp.REDIRECT_URI, "read");

        HttpResponse<String> authorize = TestHttp.get(client, authorizeUrl(clientId), "X-Account-Id", "acct-123");
        HttpResponse<String> deny = TestHttp.denyConsent(client, url(""), authorize, "acct-123");

        // RFC 6749 §4.1.2.1: denial is redirected to the client's redirect_uri with error=access_denied
        // and the client's original state — the agent can terminate cleanly instead of hanging.
        assertThat(deny.statusCode()).isEqualTo(302);
        String location = deny.headers().firstValue("Location").orElseThrow();
        assertThat(location).startsWith(TestHttp.REDIRECT_URI);
        assertThat(location).contains("error=access_denied");
        assertThat(location).doesNotContain("code=");
        assertThat(location).contains("state=xyz");
    }

    @Test
    void denyingConsentCleansUpAndConsentIsAskedAgain() throws Exception {
        String clientId = TestHttp.registerPublicClient(client, port, TestHttp.REDIRECT_URI, "read");

        HttpResponse<String> authorize = TestHttp.get(client, authorizeUrl(clientId), "X-Account-Id", "acct-123");
        HttpResponse<String> deny = TestHttp.denyConsent(client, url(""), authorize, "acct-123");
        assertThat(deny.headers().firstValue("Location").orElseThrow()).contains("error=access_denied");

        // The denial removed the pending authorization (and recorded nothing): a new authorize by the
        // same user for the same client starts over at the consent page.
        HttpResponse<String> again = TestHttp.get(client, authorizeUrl(clientId), "X-Account-Id", "acct-123");
        assertThat(again.statusCode()).isEqualTo(302);
        assertThat(again.headers().firstValue("Location").orElseThrow()).contains("/oauth2/consent");
    }

    @Test
    void recordedApprovalIsRememberedForNextAuthorization() throws Exception {
        String clientId = TestHttp.registerPublicClient(client, port, TestHttp.REDIRECT_URI, "read");

        // First round-trip goes through the consent page...
        HttpResponse<String> firstAuthorize =
                TestHttp.get(client, authorizeUrl(clientId), "X-Account-Id", "acct-123");
        assertThat(firstAuthorize.headers().firstValue("Location").orElseThrow())
                .contains("/oauth2/consent");
        HttpResponse<String> consent = TestHttp.approveConsent(client, url(""), firstAuthorize, "acct-123");
        assertThat(consent.headers().firstValue("Location").orElseThrow()).contains("code=");

        // ...the recorded approval (per user + client) short-circuits consent on the next authorize.
        HttpResponse<String> secondAuthorize =
                TestHttp.get(client, authorizeUrl(clientId), "X-Account-Id", "acct-123");
        assertThat(secondAuthorize.statusCode()).isEqualTo(302);
        String location = secondAuthorize.headers().firstValue("Location").orElseThrow();
        assertThat(location).startsWith(TestHttp.REDIRECT_URI);
        assertThat(location).contains("code=");
    }

    @Test
    void anotherUsersApprovalDoesNotShortCircuitConsent() throws Exception {
        String clientId = TestHttp.registerPublicClient(client, port, TestHttp.REDIRECT_URI, "read");

        HttpResponse<String> firstAuthorize =
                TestHttp.get(client, authorizeUrl(clientId), "X-Account-Id", "acct-123");
        HttpResponse<String> consent = TestHttp.approveConsent(client, url(""), firstAuthorize, "acct-123");
        assertThat(consent.headers().firstValue("Location").orElseThrow()).contains("code=");

        // Consents are recorded per user + client: acct-456 still has to approve for themselves.
        HttpResponse<String> otherUserAuthorize =
                TestHttp.get(client, authorizeUrl(clientId), "X-Account-Id", "acct-456");
        assertThat(otherUserAuthorize.headers().firstValue("Location").orElseThrow())
                .contains("/oauth2/consent");
    }
}
