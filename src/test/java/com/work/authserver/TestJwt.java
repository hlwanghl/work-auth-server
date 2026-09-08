package com.work.authserver;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Decodes claims from the {@code access_token} in a token-endpoint JSON response — shared helper for
 * the real-port integration tests that assert issued-token claims (iss/aud).
 */
final class TestJwt {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    private TestJwt() {
    }

    /** Decodes the payload claims of the {@code access_token} in a token-endpoint response. */
    static JsonNode claims(String tokenJson) throws Exception {
        String accessToken = MAPPER.readTree(new StringReader(tokenJson)).get("access_token").asString();
        String payload = accessToken.split("\\.")[1];
        String claimsJson = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);
        return MAPPER.readTree(new StringReader(claimsJson));
    }

    /** Decodes the {@code aud} claim (first value) of the {@code access_token}. */
    static String aud(String tokenJson) throws Exception {
        JsonNode aud = claims(tokenJson).get("aud");
        return aud.isArray() ? aud.get(0).asString() : aud.asString();
    }
}
