package com.work.authserver.discovery;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata;

import java.util.List;
import java.util.function.Consumer;

/**
 * Disclosure policy for the RFC 8414 authorization-server metadata (FR-13): the discovery document
 * advertises ONLY what this server actually enables. Spring Security's metadata endpoint hardcodes
 * its defaults into the response &mdash; six token-endpoint client-authentication methods (incl.
 * {@code private_key_jwt} and the mTLS pair, none of which is wired here) and four grant types
 * (incl. {@code client_credentials}, deliberately out of scope per docs/requirements.md §4, and
 * token exchange, never enabled) &mdash; while omitting {@code none}, the method every
 * DCR-registered MCP client (FR-7) actually uses. Minimal exposure: trim the claims to the enabled
 * set, on the token endpoint and on the revocation/introspection endpoints, which share the same
 * hardcoded default (public clients authenticate there via {@code PublicClientAuthenticationProvider}).
 *
 * <p>The enabled set mirrors the two client shapes (FR-4):
 * grants {@code authorization_code} + {@code refresh_token}; client authentication {@code none}
 * (public PKCE MCP clients, FR-7) and {@code client_secret_basic} (pre-registered website apps,
 * FR-15 &mdash; Basic only per the OAuth 2.1 draft).
 *
 * <p>Disclosure only mirrors capability; the endpoint-side enforcement is
 * client/DcrRegistrationPolicy: open DCR accepts public PKCE clients only, so no dynamically
 * registered client ever holds a grant or authentication method outside this set (the pre-registered
 * website apps hold exactly {@code client_secret_basic} + auth code/refresh, see
 * client/PreRegisteredClients).
 */
public final class DiscoveryMetadataPolicy {

    private static final List<String> ENABLED_GRANT_TYPES = List.of(
            AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
            AuthorizationGrantType.REFRESH_TOKEN.getValue());

    private static final List<String> ENABLED_CLIENT_AUTHENTICATION_METHODS = List.of(
            ClientAuthenticationMethod.NONE.getValue(),
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());

    private DiscoveryMetadataPolicy() {
    }

    /** Consumer for {@code authorizationServerMetadataEndpoint(...)}'s metadata customizer. */
    public static Consumer<OAuth2AuthorizationServerMetadata.Builder> advertiseOnlyEnabledCapabilities() {
        return metadata -> {
            metadata.grantTypes(replaceWith(ENABLED_GRANT_TYPES));
            metadata.tokenEndpointAuthenticationMethods(replaceWith(ENABLED_CLIENT_AUTHENTICATION_METHODS));
            metadata.tokenRevocationEndpointAuthenticationMethods(replaceWith(ENABLED_CLIENT_AUTHENTICATION_METHODS));
            metadata.tokenIntrospectionEndpointAuthenticationMethods(replaceWith(ENABLED_CLIENT_AUTHENTICATION_METHODS));
        };
    }

    /**
     * The default customizer hands over its hardcoded list, so the consumer can edit it in place —
     * replacement (not just removal): Spring omits {@code none} from the defaults even though it is
     * the method of every dynamically registered MCP client.
     */
    private static Consumer<List<String>> replaceWith(List<String> enabled) {
        return advertised -> {
            advertised.clear();
            advertised.addAll(enabled);
        };
    }
}
