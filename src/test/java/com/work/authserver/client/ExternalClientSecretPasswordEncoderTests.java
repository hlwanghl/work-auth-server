package com.work.authserver.client;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the dispatch of the client-secret PasswordEncoder (FR-16 in docs/requirements.md): the
 * {@code {noop}} prefix compares verbatim (dev), the {@code {ext}} prefix delegates the decision to
 * the {@link ClientCredentialVerifier} (external registry), and anything else never matches.
 */
class ExternalClientSecretPasswordEncoderTests {

    private final ClientCredentialVerifier fakeVerifier = (clientId, clientSecret) ->
            clientId.equals("web-app") && clientSecret.equals("the-real-secret")
                    ? Optional.of(new ClientCredentialVerifier.VerifiedClient(clientId, "acct-1"))
                    : Optional.empty();

    @Test
    void plainPrefixComparesVerbatim() {
        ExternalClientSecretPasswordEncoder encoder = new ExternalClientSecretPasswordEncoder(null);

        assertThat(encoder.matches("s3cret", "{noop}s3cret")).isTrue();
        assertThat(encoder.matches("other", "{noop}s3cret")).isFalse();
        assertThat(encoder.matches("s3cret", "{noop}")).isFalse();
    }

    @Test
    void externalPrefixDelegatesToVerifier() {
        ExternalClientSecretPasswordEncoder encoder = new ExternalClientSecretPasswordEncoder(fakeVerifier);

        assertThat(encoder.matches("the-real-secret", "{ext}web-app")).isTrue();
        assertThat(encoder.matches("wrong-secret", "{ext}web-app")).isFalse();
        assertThat(encoder.matches("the-real-secret", "{ext}unknown-client")).isFalse();
    }

    @Test
    void externalPrefixWithoutVerifierNeverMatches() {
        // Registry disabled: no {ext} storage is ever produced, but even if it were, no decision.
        ExternalClientSecretPasswordEncoder encoder = new ExternalClientSecretPasswordEncoder(null);

        assertThat(encoder.matches("anything", "{ext}web-app")).isFalse();
    }

    @Test
    void unknownPrefixAndNullsNeverMatch() {
        ExternalClientSecretPasswordEncoder encoder = new ExternalClientSecretPasswordEncoder(fakeVerifier);

        assertThat(encoder.matches("x", "ciphertext")).isFalse();
        assertThat(encoder.matches(null, "{noop}s3cret")).isFalse();
        assertThat(encoder.matches("s3cret", null)).isFalse();
    }
}
