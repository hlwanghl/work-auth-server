package com.work.authserver.client;

import java.util.Optional;

/**
 * Verifies a confidential client's credentials against the client registry (FR-16 in
 * docs/requirements.md). The production implementation calls the external REST API; the verification
 * result's {@code accountId} identifies the account the client belongs to in the registry's world,
 * and is the contract for future token enrichment (docs/architecture.md §9) — verification alone
 * decides authentication. Extra fields the API may return are ignored; promote one to a named
 * component here when a consumer actually needs it.
 */
public interface ClientCredentialVerifier {

    /**
     * @return the verified client (with its accountId) if and only if the credentials are valid;
     *         empty for ANY failure — invalid credentials, unknown client, API error, timeout.
     */
    Optional<VerifiedClient> verify(String clientId, String clientSecret);

    record VerifiedClient(String clientId, String accountId) {
    }
}
