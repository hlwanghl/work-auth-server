package com.work.authserver.web;

import com.work.authserver.identity.Account;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.util.List;

/**
 * The consent page (FR-5 in docs/requirements.md): renders the authorization request the user is
 * about to approve — the client and the scopes it requests — with two outcomes. <b>同意</b> posts the
 * checked scopes back to the authorize endpoint ({@code client_id} + {@code state} + {@code scope}),
 * which is what Spring AS's built-in consent provider consumes to issue the code. <b>拒绝</b> posts
 * the same identifying parameters with NO scopes — Spring AS treats an empty scope set as the user's
 * denial: it revokes any saved consent, removes the pending authorization, and the client receives
 * {@code error=access_denied} per RFC 6749 §4.1.2.1.
 *
 * <p>This server sits on the default filter chain, so an unauthenticated user is redirected to the
 * SSO before ever seeing the page (a user must be logged in to consent). The page is stateless
 * (NFR-1): the pending authorization lives in the {@code OAuth2AuthorizationService} keyed by the
 * {@code state} below, and the recorded approval lives in the {@code OAuth2AuthorizationConsentService}
 * (per user + client), so a later authorization by the same user for the same client skips this page.
 *
 * <p>The forms' action and parameter names are the contract Spring AS expects; everything echoed into
 * the HTML is escaped (client_id/state come from the query string).
 */
@RestController
public class ConsentController {

    @GetMapping(value = "/oauth2/consent", produces = MediaType.TEXT_HTML_VALUE)
    public String consent(@AuthenticationPrincipal Account account,
                          @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                          @RequestParam(OAuth2ParameterNames.STATE) String state,
                          @RequestParam(value = OAuth2ParameterNames.SCOPE, required = false) List<String> scopes) {

        StringBuilder scopeCheckboxes = new StringBuilder();
        if (scopes != null) {
            for (String scope : scopes) {
                String escaped = HtmlUtils.htmlEscape(scope);
                scopeCheckboxes
                        .append("<label><input type=\"checkbox\" name=\"").append(OAuth2ParameterNames.SCOPE)
                        .append("\" value=\"").append(escaped).append("\" checked> ").append(escaped)
                        .append("</label><br>");
            }
        }
        String escapedClientId = HtmlUtils.htmlEscape(clientId);
        String hiddenFields = """
                        <input type="hidden" name="%s" value="%s">
                        <input type="hidden" name="%s" value="%s">
                        """.formatted(
                OAuth2ParameterNames.CLIENT_ID, escapedClientId,
                OAuth2ParameterNames.STATE, HtmlUtils.htmlEscape(state));
        return """
                <!DOCTYPE html>
                <html lang="zh">
                <head><meta charset="UTF-8"><title>授权确认</title></head>
                <body>
                  <h1>授权请求</h1>
                  <p>账号 <b>%s</b>（%s）：客户端 <b>%s</b> 正在请求以下权限：</p>
                  <form method="post" action="/oauth2/authorize">
                    %s
                    %s
                    <p><button type="submit">同意</button></p>
                  </form>
                  <form method="post" action="/oauth2/authorize">
                    %s
                    <p><button type="submit">拒绝</button></p>
                  </form>
                </body>
                </html>
                """.formatted(
                HtmlUtils.htmlEscape(account.getUsername()),
                HtmlUtils.htmlEscape(account.getAccountId()),
                escapedClientId,
                hiddenFields,
                scopeCheckboxes.toString(),
                hiddenFields);
    }
}
