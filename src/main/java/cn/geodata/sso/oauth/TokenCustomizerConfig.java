package cn.geodata.sso.oauth;

import cn.geodata.sso.cas.attr.CasPrincipalAttributes;
import cn.geodata.sso.user.CasUserPrincipal;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * Injects the claims from architecture 4.2, staying within the "minimum necessary" rule: no full
 * permission set, no org tree, no phone number beyond the single {@code phone_number} claim.
 *
 * <p>Both token surfaces read the same principal attribute map, so the CAS XML dialect and the OIDC
 * claims can never disagree about a user's name or unit.
 */
@Configuration
public class TokenCustomizerConfig {

    private static final String ACCESS_TOKEN = "access_token";

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            var claims = context.getClaims();
            var client = context.getRegisteredClient();
            claims.claim("client_id", client.getClientId());
            claims.claim("ver", 1);

            Object rawPrincipal = context.getPrincipal() == null ? null : context.getPrincipal().getPrincipal();
            if (rawPrincipal instanceof CasUserPrincipal user) {
                Map<String, Object> attrs = user.getAttributes();
                claims.claim("preferred_username", user.getUsername());
                putIfPresent(claims, "name", attrs.get(CasPrincipalAttributes.REAL_NAME));
                putIfPresent(claims, "email", attrs.get(CasPrincipalAttributes.EMAIL));
                putIfPresent(claims, "phone_number", attrs.get(CasPrincipalAttributes.MOBILE));
                putIfPresent(claims, "org", attrs.get(CasPrincipalAttributes.WORK_FOR));
                putIfPresent(claims, "source", attrs.get(CasPrincipalAttributes.CREATED_FROM));
                putIfPresent(claims, "active", attrs.get(CasPrincipalAttributes.IS_ENABLED));
                claims.claim("roles", java.util.List.of("ROLE_USER"));
                if (user.getUserId() != null) {
                    // sub = the business key (t_customer.userid), so downstream systems keep the same
                    // identity they already stored; architecture 5.7.2 lists it as a sub candidate.
                    claims.subject(user.getUserId());
                }
            } else if (context.getTokenType() != null
                    && ACCESS_TOKEN.equals(context.getTokenType().getValue())
                    && context.getAuthorizationGrantType() != null
                    && "client_credentials".equals(context.getAuthorizationGrantType().getValue())) {
                // Service identity: architecture 3.2 forbids carrying a user-like sub here.
                claims.subject(client.getClientId());
                claims.claim("actor_type", "SERVICE");
            }
        };
    }

    private static void putIfPresent(org.springframework.security.oauth2.jwt.JwtClaimsSet.Builder claims,
                                     String name, Object value) {
        if (value != null) {
            claims.claim(name, value);
        }
    }
}
