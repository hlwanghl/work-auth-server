package com.work.authserver.client;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * In-memory {@link RegisteredClientRepository} that bounds storage by evicting idle
 * dynamically-registered clients &mdash; the cleanup half of keeping open DCR (RFC 7591) safe on a
 * public origin (the rate limit at the gateway stops a flood; this reaps what still got created).
 *
 * <p><b>Eviction rule:</b> a client is reaped when {@code now - lastSeen > evictUnusedAfter} <em>and</em>
 * it is not on the static-client whitelist. Reads ({@link #findById} / {@link #findByClientId}) refresh
 * {@code lastSeen}, so a client that is actually being used (authorize / token / introspect) is never
 * reaped &mdash; only registrations that were created and then abandoned. The seeded static demo clients
 * ({@code demo-client}, {@code mcp-agent}) are whitelisted by {@code clientId} and never evicted (their
 * {@code id}s are random per-startup, so the whitelist keys on the stable {@code clientId}).
 *
 * <p>This is an interim single-instance store (lost on restart). Phase 4 replaces it with a persistent
 * JDBC repository and a real client-lifetime policy; the eviction rule is deliberately conservative so
 * it is safe to ship now. The millis-clock is injectable solely so the unit test can advance time
 * deterministically instead of sleeping.
 */
public class ExpiringRegisteredClientRepository implements RegisteredClientRepository {

    private final ConcurrentHashMap<String, Entry> clientsById = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> idByClientId = new ConcurrentHashMap<>();
    private final Set<String> whitelist = new HashSet<>();
    private final Duration evictUnusedAfter;
    private final LongSupplier clock;

    public ExpiringRegisteredClientRepository(List<RegisteredClient> seed, Duration evictUnusedAfter) {
        this(seed, evictUnusedAfter, System::currentTimeMillis);
    }

    /** Test seam: inject a controllable clock so eviction is deterministic without sleeping. */
    ExpiringRegisteredClientRepository(List<RegisteredClient> seed, Duration evictUnusedAfter, LongSupplier clock) {
        this.evictUnusedAfter = evictUnusedAfter;
        this.clock = clock;
        // Seed the static demo clients and whitelist them so they are never evicted.
        for (RegisteredClient client : seed) {
            this.whitelist.add(client.getClientId());
            save(client);
        }
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
     * Reap idle, non-whitelisted clients (every 10 minutes). Cadence is fixed; a flood's worth of
     * idle entries lives at most until the next sweep, bounded by the per-IP limit at the gateway.
     */
    @Scheduled(fixedDelay = 600_000)
    void sweep() {
        long cutoff = clock.getAsLong() - evictUnusedAfter.toMillis();
        clientsById.entrySet().removeIf(e -> {
            Entry entry = e.getValue();
            return entry.lastSeen < cutoff && !whitelist.contains(entry.client.getClientId());
        });
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
