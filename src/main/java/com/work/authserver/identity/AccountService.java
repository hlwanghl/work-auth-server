package com.work.authserver.identity;

import java.util.Optional;

/**
 * Resolves a user from their account id (the value of the {@code X-Account-Id} header).
 * Swap {@link InMemoryAccountService} for a JPA/remote-backed implementation in production.
 */
public interface AccountService {

    Optional<Account> findByAccountId(String accountId);
}
