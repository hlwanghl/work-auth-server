package com.work.authserver.identity;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class InMemoryAccountService implements AccountService {

    private final Map<String, Account> accounts = new ConcurrentHashMap<>();

    public InMemoryAccountService() {
        save("acct-123", "alice", List.of("ROLE_USER", "read", "write"));
        save("acct-456", "bob", List.of("ROLE_USER", "read"));
    }

    private void save(String accountId, String username, List<String> authorities) {
        accounts.put(accountId, new Account(
                accountId,
                username,
                authorities.stream().map(SimpleGrantedAuthority::new).toList()));
    }

    @Override
    public Optional<Account> findByAccountId(String accountId) {
        if (accountId == null || accountId.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(accounts.get(accountId));
    }
}
