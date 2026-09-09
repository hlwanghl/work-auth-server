package com.work.authserver.client;

import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * The {@link PasswordEncoder} behind client-secret authentication — the one seam where "how a stored
 * secret is checked" can be swapped without touching any Spring protocol logic (FR-16 in
 * docs/requirements.md). Dispatches on the prefix of the STORED value (which
 * {@link PreRegisteredClients} controls):
 *
 * <ul>
 *   <li>{@code {noop}<secret>} — dev mode: constant-time verbatim comparison against the configured
 *       secret;</li>
 *   <li>{@code {ext}<clientId>} — external-registry mode: the stored value carries no secret at all,
 *       only the client_id; the presented secret is verified by the {@link ClientCredentialVerifier}
 *       (the REST API owns the real secret). With no verifier wired (registry disabled) this never
 *       matches.</li>
 * </ul>
 */
public final class ExternalClientSecretPasswordEncoder implements PasswordEncoder {

    static final String EXTERNAL_PREFIX = "{ext}";
    static final String PLAIN_PREFIX = "{noop}";

    private final ClientCredentialVerifier verifier;

    public ExternalClientSecretPasswordEncoder(ClientCredentialVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) {
            return false;
        }
        String presented = rawPassword.toString();
        if (encodedPassword.startsWith(EXTERNAL_PREFIX)) {
            String clientId = encodedPassword.substring(EXTERNAL_PREFIX.length());
            return verifier != null && !clientId.isBlank()
                    && verifier.verify(clientId, presented).isPresent();
        }
        if (encodedPassword.startsWith(PLAIN_PREFIX)) {
            return MessageDigest.isEqual(
                    presented.getBytes(StandardCharsets.UTF_8),
                    encodedPassword.substring(PLAIN_PREFIX.length()).getBytes(StandardCharsets.UTF_8));
        }
        return false;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        // Storage is decided by configuration ({noop}/{ext} markers), never by encoding requests.
        throw new UnsupportedOperationException(
                "Client secrets are stored via PreRegisteredClients, not encoded");
    }

    @Override
    public boolean upgradeEncoding(String encodedPassword) {
        return false;
    }
}
