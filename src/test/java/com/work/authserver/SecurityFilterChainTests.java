package com.work.authserver;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.http.HttpClient;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Header-based authentication vs. external-SSO redirect behaviour on the default filter chain,
 * exercised over real HTTP.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SecurityFilterChainTests {

    @LocalServerPort
    private int port;

    private final HttpClient client = TestHttp.client();

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void missingHeaderRedirectsToSsoWithReturnTo() throws Exception {
        HttpResponse<String> response = TestHttp.get(client, url("/api/me"));

        assertThat(response.statusCode()).isEqualTo(302);
        String location = response.headers().firstValue("Location").orElseThrow();
        assertThat(location).startsWith("https://sso.example.com/login");
        assertThat(location).contains("return_to=");
        assertThat(location).contains("/api/me");
    }

    @Test
    void validHeaderReturnsAccount() throws Exception {
        HttpResponse<String> response =
                TestHttp.get(client, url("/api/me"), "X-Account-Id", "acct-123");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("\"accountId\":\"acct-123\"", "\"username\":\"alice\"");
    }

    @Test
    void unknownAccountRedirectsToSso() throws Exception {
        HttpResponse<String> response =
                TestHttp.get(client, url("/api/me"), "X-Account-Id", "nobody");

        assertThat(response.statusCode()).isEqualTo(302);
        assertThat(response.headers().firstValue("Location").orElseThrow())
                .startsWith("https://sso.example.com/login");
    }
}
