package com.work.authserver.web;

import com.work.authserver.user.Account;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class MeController {

    /** Small landing page to confirm the server is up. */
    @GetMapping("/")
    public Map<String, String> index() {
        return Map.of(
                "service", "work-auth-server",
                "status", "UP",
                "me", "/api/me",
                "jwks", "/oauth2/jwks",
                "authorize", "/oauth2/authorize");
    }

    /** Returns the account resolved from the X-Account-Id header. Requires authentication. */
    @GetMapping("/api/me")
    public MeResponse me(@AuthenticationPrincipal Account account) {
        List<String> authorities = account.getAuthorities().stream()
                .map(a -> a.getAuthority())
                .toList();
        return new MeResponse(account.getAccountId(), account.getUsername(), authorities);
    }

    public record MeResponse(String accountId, String username, List<String> authorities) {
    }
}
