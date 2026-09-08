package com.work.authserver.client;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plain unit test of the eviction rule with an injectable clock (no Spring context, no sleeping).
 * Pins: the repository starts empty (no static clients, FR-6 in docs/requirements.md); an idle client
 * is reaped past the TTL; a read refreshes {@code lastSeen} so an actively-used client survives.
 */
class ExpiringRegisteredClientRepositoryTests {

    private final AtomicLong millis = new AtomicLong(1_000_000L);

    private ExpiringRegisteredClientRepository repo(Duration ttl) {
        return new ExpiringRegisteredClientRepository(ttl, millis::get);
    }

    private static RegisteredClient client(String id, String clientId) {
        return RegisteredClient.withId(id)
                .clientId(clientId)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://127.0.0.1:0/cb")
                .scope("read")
                .build();
    }

    @Test
    void startsEmpty() {
        assertThat(repo(Duration.ofMillis(100)).size()).isZero();
    }

    @Test
    void idleClientIsReapedAfterTtl() {
        ExpiringRegisteredClientRepository repo = repo(Duration.ofMillis(100));
        repo.save(client("id-dyn", "dynamic-1"));
        assertThat(repo.findByClientId("dynamic-1")).isNotNull();

        // Idle past the TTL, never read in the meantime.
        millis.addAndGet(10_000);
        repo.sweep();

        assertThat(repo.findById("id-dyn")).isNull();
        assertThat(repo.findByClientId("dynamic-1")).isNull();
    }

    @Test
    void recentlyReadClientSurvives() {
        ExpiringRegisteredClientRepository repo = repo(Duration.ofMillis(100));
        repo.save(client("id-dyn", "dynamic-1"));
        // Advance less than the TTL, then read -> lastSeen refreshed to now.
        millis.addAndGet(50);
        assertThat(repo.findByClientId("dynamic-1")).isNotNull();
        // Another step that is < TTL since the last read -> still within the window.
        millis.addAndGet(50);
        repo.sweep();
        assertThat(repo.findByClientId("dynamic-1")).isNotNull();
    }

    @Test
    void repeatedReadsKeepClientAliveBeyondRawTtl() {
        ExpiringRegisteredClientRepository repo = repo(Duration.ofMillis(100));
        repo.save(client("id-dyn", "dynamic-1"));

        // Each read resets the clock; over a span far beyond the raw TTL, an in-use client stays.
        for (int i = 0; i < 5; i++) {
            millis.addAndGet(80); // < TTL per hop
            assertThat(repo.findByClientId("dynamic-1")).isNotNull();
        }
        repo.sweep();
        assertThat(repo.findByClientId("dynamic-1")).isNotNull();
    }
}
