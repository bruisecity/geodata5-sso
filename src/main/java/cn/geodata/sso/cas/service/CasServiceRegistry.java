package cn.geodata.sso.cas.service;

import cn.geodata.sso.config.SsoProperties;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Service registration and authorization check (architecture 5.2B).
 *
 * <p>Legacy facts that must NOT be copied: {@code deployerConfigContext.xml:97} wired
 * {@code InMemoryServiceRegistryDaoImpl} with <em>zero</em> initial services, while
 * {@code login-webflow.xml:40-58} forced {@code serviceAuthorizationCheck}, whose logic rejects any
 * non-empty {@code service} that is not found or not enabled. Combined, that means every
 * service-bearing login should have been rejected, which contradicts the fact that production
 * works. So the new system stores registrations in PostgreSQL and offers two modes:
 *
 * <ul>
 *   <li>{@link SsoProperties.ServiceRegistryMode#LENIENT} (default): a non-empty {@code service} is
 *       accepted and the ticket is still validated. This matches the historical reality of
 *       unregistered legacy apps.</li>
 *   <li>{@link SsoProperties.ServiceRegistryMode#STRICT}: only services present and enabled in
 *       {@code cas_service_registry} are allowed. Registers must be completed before enabling.</li>
 * </ul>
 *
 * <p>Pattern matching follows the legacy {@code RegexRegisteredService} semantics: the stored
 * pattern is matched against the full service URL using {@code String.matches}, and the most
 * specific (longest) matching pattern wins so a broad rule cannot shadow a narrow one.
 */
@Component
public class CasServiceRegistry {

    private final SsoProperties props;
    private final JdbcTemplate jdbc;

    public CasServiceRegistry(SsoProperties props, JdbcTemplate jdbc) {
        this.props = props;
        this.jdbc = jdbc;
    }

    /**
     * @param service the raw {@code service} request parameter
     * @return true when the service may proceed to ticket issue / validation
     */
    public boolean isAllowed(String service) {
        if (service == null || service.isBlank()) {
            // Legacy: empty service was let through by ServiceAuthorizationCheck.
            return false;
        }
        if (!isAbsoluteHttpUrl(service)) {
            // Legacy registered-service matching required a URL; relative values never matched.
            return false;
        }
        if (props.getCas().getServiceRegistryMode() == SsoProperties.ServiceRegistryMode.LENIENT) {
            return true;
        }
        return findMatching(service).map(RegisteredService::enabled).orElse(false);
    }

    public boolean isStrictMode() {
        return props.getCas().getServiceRegistryMode() == SsoProperties.ServiceRegistryMode.STRICT;
    }

    /** Most-specific enabled-or-not match, used for diagnostics and for strict-mode decisions. */
    public java.util.Optional<RegisteredService> findMatching(String service) {
        List<RegisteredService> candidates;
        try {
            candidates = jdbc.query(
                    "select id, service_pattern, name, enabled, allow_proxy from cas_service_registry order by id",
                    (rs, i) -> new RegisteredService(
                            rs.getLong("id"),
                            rs.getString("service_pattern"),
                            rs.getString("name"),
                            rs.getBoolean("enabled"),
                            rs.getBoolean("allow_proxy")));
        } catch (RuntimeException ex) {
            // Table not migrated yet: behave as an empty registry.
            candidates = List.of();
        }
        RegisteredService best = null;
        for (RegisteredService s : candidates) {
            if (s.matches(service)) {
                if (best == null || s.servicePattern().length() > best.servicePattern().length()) {
                    best = s;
                }
            }
        }
        return java.util.Optional.ofNullable(best);
    }

    private static boolean isAbsoluteHttpUrl(String s) {
        String lower = s.toLowerCase();
        return (lower.startsWith("http://") || lower.startsWith("https://")) && !s.contains(" ");
    }

    public record RegisteredService(long id, String servicePattern, String name, boolean enabled, boolean allowProxy) {

        /** Regex match against the whole service URL, legacy {@code RegexRegisteredService} style. */
        public boolean matches(String service) {
            try {
                return service.matches(servicePattern);
            } catch (java.util.regex.PatternSyntaxException ex) {
                return false;
            }
        }
    }
}
