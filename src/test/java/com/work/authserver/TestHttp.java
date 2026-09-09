package com.work.authserver;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Minimal HTTP helpers for real-port integration tests using the built-in {@link HttpClient}.
 * Real HTTP (rather than MockMvc) is used because the OAuth2 authorization endpoint is exercised
 * end-to-end, mirroring how a browser/client would call the server.
 *
 * <p>The server has no static clients (FR-6 in docs/requirements.md): tests obtain a client via
 * {@link #registerPublicClient} (open DCR) and drive the consent step via {@link #approveConsent},
 * exactly as an MCP client would.
 */
final class TestHttp {

    static final String REDIRECT_URI = "http://127.0.0.1:8080/callback";
    static final String ACCOUNT_ID_HEADER = "X-Account-Id";

    private static final Pattern CLIENT_ID = Pattern.compile("\"client_id\":\"([^\"]+)\"");

    private TestHttp() {
    }

    static HttpClient client() {
        return HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /**
     * Registers a public PKCE client via open DCR (RFC 7591) and returns its client_id — the only way
     * tests obtain a client (FR-6/FR-7).
     */
    static String registerPublicClient(HttpClient client, int port, String redirectUri, String scope) throws Exception {
        String registration = """
                {
                  "client_name": "integration-test-agent",
                  "redirect_uris": ["%s"],
                  "grant_types": ["authorization_code", "refresh_token"],
                  "response_types": ["code"],
                  "token_endpoint_auth_method": "none",
                  "scope": "%s"
                }
                """.formatted(redirectUri, scope);
        HttpResponse<String> response = postJson(client, "http://localhost:" + port + "/oauth2/register", registration);
        if (response.statusCode() != 201) {
            throw new IllegalStateException("DCR failed: " + response.statusCode() + " " + response.body());
        }
        Matcher matcher = CLIENT_ID.matcher(response.body());
        if (!matcher.find()) {
            throw new IllegalStateException("no client_id in DCR response: " + response.body());
        }
        return matcher.group(1);
    }

    /**
     * Drives the consent step (FR-5): when the authorize response redirects to the consent page
     * (absolute URL), submits the approval form back to the authorize endpoint as the given account
     * (the same user must approve). Passes through any response that is not a consent redirect, so
     * callers can chain this after every authorize call regardless of whether consent was required.
     */
    static HttpResponse<String> approveConsent(HttpClient client, String baseUrl,
                                               HttpResponse<String> authorizeResponse, String accountId) throws Exception {
        String location = authorizeResponse.headers().firstValue("Location").orElse("");
        if (!location.contains("/oauth2/consent")) {
            return authorizeResponse;
        }
        StringBuilder body = new StringBuilder("client_id=")
                .append(URLEncoder.encode(parseQueryValues(location, "client_id").get(0), StandardCharsets.UTF_8))
                .append("&state=")
                .append(URLEncoder.encode(parseQueryValues(location, "state").get(0), StandardCharsets.UTF_8));
        for (String scope : parseQueryValues(location, "scope")) {
            body.append("&scope=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8));
        }
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/oauth2/authorize"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header(ACCOUNT_ID_HEADER, accountId)
                .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    /**
     * Drives the deny step (FR-5): submits the consent form WITHOUT any scopes, which Spring AS's
     * consent provider treats as the user's denial — the pending authorization is removed and the
     * client receives {@code error=access_denied} (RFC 6749 §4.1.2.1).
     */
    static HttpResponse<String> denyConsent(HttpClient client, String baseUrl,
                                            HttpResponse<String> authorizeResponse, String accountId) throws Exception {
        String location = authorizeResponse.headers().firstValue("Location").orElse("");
        if (!location.contains("/oauth2/consent")) {
            throw new IllegalStateException("authorize did not lead to the consent page: " + location);
        }
        StringBuilder body = new StringBuilder("client_id=")
                .append(URLEncoder.encode(parseQueryValues(location, "client_id").get(0), StandardCharsets.UTF_8))
                .append("&state=")
                .append(URLEncoder.encode(parseQueryValues(location, "state").get(0), StandardCharsets.UTF_8));
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/oauth2/authorize"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header(ACCOUNT_ID_HEADER, accountId)
                .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    static HttpResponse<String> get(HttpClient client, String url, String... headers) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url)).GET();
        for (int i = 0; i + 1 < headers.length; i += 2) {
            builder.header(headers[i], headers[i + 1]);
        }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    static HttpResponse<String> postForm(HttpClient client, String url, Map<String, String> form,
                                         String... headers) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody(form), StandardCharsets.UTF_8));
        for (int i = 0; i + 1 < headers.length; i += 2) {
            builder.header(headers[i], headers[i + 1]);
        }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    /** HTTP Basic authorization header value for client-secret authentication. */
    static String basicAuth(String username, String secret) {
        String credentials = username + ":" + secret;
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    static HttpResponse<String> postJson(HttpClient client, String url, String jsonBody) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    static String formBody(Map<String, String> form) {
        StringBuilder body = new StringBuilder();
        form.forEach((key, value) -> {
            if (body.length() > 0) {
                body.append('&');
            }
            body.append(URLEncoder.encode(key, StandardCharsets.UTF_8))
                    .append('=')
                    .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        });
        return body.toString();
    }

    static Map<String, String> parseQuery(String url) {
        Map<String, String> params = new LinkedHashMap<>();
        int queryIndex = url.indexOf('?');
        String query = queryIndex < 0 ? "" : url.substring(queryIndex + 1);
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                params.put(pair.substring(0, eq), pair.substring(eq + 1));
            }
        }
        return params;
    }

    /** All values of a (possibly repeated) query parameter, URL-decoded. */
    static List<String> parseQueryValues(String url, String key) {
        List<String> values = new ArrayList<>();
        int queryIndex = url.indexOf('?');
        String query = queryIndex < 0 ? "" : url.substring(queryIndex + 1);
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0 && key.equals(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8))) {
                values.add(URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            }
        }
        return values;
    }

    static String s256(String verifier) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }
}
