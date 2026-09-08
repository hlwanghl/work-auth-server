package com.work.authserver.client;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * In-memory {@link RegisteredClientRepository} that bounds storage by evicting idle dynamically-registered
 * clients &mdash; the cleanup half of keeping open DCR (RFC 7591) safe on a public origin (the rate limit
 * at the gateway stops a flood; this reaps what still got created). The repository starts EMPTY: this
 * server ships no static clients &mdash; every client is an MCP client that self-registered via open DCR
 * (FR-6/FR-7 in docs/requirements.md).
 *
 * <p><b>Eviction rule:</b> a client is reaped when {@code now - lastSeen > evictUnusedAfter}. Reads
 * ({@link #findById} / {@link #findByClientId}) refresh {@code lastSeen}, so a client that is actually
 * being used (authorize / token / introspect) is never reaped &mdash; only registrations that were
 * created and then abandoned.
 *
 * <p>This is an interim single-instance store (lost on restart). It is replaced by a persistent (JDBC)
 * repository and a real client-lifetime policy before production; the eviction rule is deliberately
 * conservative so it is safe to ship now. The millis-clock is injectable solely so the unit test can
 * advance time deterministically instead of sleeping.
 */
public class ExpiringRegisteredClientRepository implements RegisteredClientRepository {

    private final ConcurrentHashMap<String, Entry> clientsById = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> idByClientId = new ConcurrentHashMap<>();
    private final Duration evictUnusedAfter;
    private final LongSupplier clock;

    public ExpiringRegisteredClientRepository(Duration evictUnusedAfter) {
        this(evictUnusedAfter, System::currentTimeMillis);
    }

    /** Test seam: inject a controllable clock so eviction is deterministic without sleeping. */
    ExpiringRegisteredClientRepository(Duration evictUnusedAfter, LongSupplier clock) {
        this.evictUnusedAfter = evictUnusedAfter;
        this.clock = clock;
    }

    @Override
    public void save(RegisteredClient client) {
        long now = clock.getAsLong();
        clientsById.put(client.getId(), new Entry(client, now));
        idByClientId.put(client.getClientId(), client.getId());
    }

    @Override
    public RegisteredClient findById(String id) {
        Entry entry = clientsById.get(id);
        if (entry == null) {
            return null;
        }
        // A read is use: refresh lastSeen so active clients survive eviction.
        entry.lastSeen = clock.getAsLong();
        return entry.client;
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        String id = idByClientId.get(clientId);
        return id == null ? null : findById(id);
    }

    /**
     * Reap idle clients (every 10 minutes). Cadence is fixed; a flood's worth of idle entries lives at
     * most until the next sweep, bounded by the per-IP limit at the gateway.
     */
    @Scheduled(fixedDelay = 600_000)
    void sweep() {
        long cutoff = clock.getAsLong() - evictUnusedAfter.toMillis();
        clientsById.entrySet().removeIf(e -> e.getValue().lastSeen < cutoff);
        // Drop index entries whose client was just removed.
        idByClientId.entrySet().removeIf(e -> !clientsById.containsKey(e.getValue()));
    }

    int size() {
        return clientsById.size();
    }

    private static final class Entry {
        final RegisteredClient client;
        volatile long lastSeen;

        Entry(RegisteredClient client, long lastSeen) {
            this.client = client;
            this.lastSeen = lastSeen;
        }
    }
}
