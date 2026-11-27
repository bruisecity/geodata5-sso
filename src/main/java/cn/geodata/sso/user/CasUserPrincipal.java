package cn.geodata.sso.user;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.security.core.GrantedAuthority;

/**
 * Authenticated principal.
 *
 * <p>Deliberately carries the raw attribute map produced by
 * {@link cn.geodata.sso.user.LegacyUserRepository#toPrincipalAttributes}. Both the CAS layer (which
 * then maps them through {@code cas_attribute_mapping}) and the OIDC layer (which maps them to
 * claims) read this same map, so the two surfaces cannot drift apart.
 *
 * <p>Serializable because the legacy server stored the assertion attributes in the HTTP session
 * ({@code casAttributes}); Spring Session with Redis requires the same property.
 */
public class CasUserPrincipal implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String username;
    private final String userId;
    private final Map<String, Object> attributes;
    private final transient List<GrantedAuthority> authorities;

    public CasUserPrincipal(String username, String userId, Map<String, Object> attributes,
                            List<GrantedAuthority> authorities) {
        this.username = username;
        this.userId = userId;
        this.attributes = attributes;
        this.authorities = authorities;
    }

    public String getUsername() {
        return username;
    }

    public String getUserId() {
        return userId;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public List<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    /** Convenience accessor mirroring the legacy {@code AuthenticationUtils.getCasAttributes(String)}. */
    public String attribute(String key) {
        Object v = attributes == null ? null : attributes.get(key);
        return v == null ? null : v.toString();
    }

    @Override
    public String toString() {
        return "CasUserPrincipal[" + username + "]";
    }
}
