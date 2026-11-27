package cn.geodata.sso.user;

import cn.geodata.sso.cas.attr.CasPrincipalAttributes;
import cn.geodata.sso.config.SsoProperties;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Data access for the legacy user table, strategy S1: same database, read-only sharing
 * (architecture 5.7.4).
 *
 * <p>Two hard rules from the source analysis:
 *
 * <ol>
 *   <li><strong>The legacy password is {@code hex_md5(password + "{" + username + "}")}</strong>
 *       computed in the browser ({@code casLoginView.jsp:24-28}, {@code res/js/md5.js:21}) and
 *       stored as-is; the server compared it as <em>plain text</em>
 *       ({@code MyQueryDatabaseAuthenticationHandler:42,78}). It therefore cannot be re-hashed:
 *       hashing the MD5 value again would mean the user's real password never matches.</li>
 *   <li><strong>Never write back to {@code t_customer}</strong>. Login counters, lock flags and
 *       last-login timestamps go to our own extension table, or they collide with the legacy
 *       {@code is_password_invalid} lock logic (30 min window / 5 failures).</li>
 * </ol>
 *
 * <p>On a successful legacy login the BCrypt hash and the upgrade flag are written <em>in the same
 * transaction</em>, so the next login takes the modern path and a crash cannot leave the account
 * in a half-upgraded state.
 */
@Component
public class LegacyUserRepository {

    private final JdbcTemplate jdbc;
    private final SsoProperties props;
    private final PasswordEncoder passwordEncoder;

    public LegacyUserRepository(JdbcTemplate jdbc, SsoProperties props, PasswordEncoder passwordEncoder) {
        this.jdbc = jdbc;
        this.props = props;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Loads the full legacy record, including all eight outward attributes and the credential state.
     */
    public Optional<LegacyUser> findByUsername(String username) {
        SsoProperties.Legacy l = props.getLegacy();
        String sql = "select "
                + l.getUsernameColumn() + " as username, "
                + l.getUserIdColumn() + " as userid, "
                + l.getRealNameColumn() + " as real_name, "
                + l.getWorkForColumn() + " as work_for, "
                + l.getEmailColumn() + " as email, "
                + l.getMobileColumn() + " as mobile, "
                + l.getCreatedFromColumn() + " as created_from, "
                + l.getEnabledColumn() + " as enabled, "
                + l.getPasswordColumn() + " as password "
                + "from " + l.getTable()
                + " where " + l.getUsernameColumn() + " = ?";
        List<LegacyUser> rows = jdbc.query(sql, LEGACY_ROW_MAPPER, username);
        return rows.stream().findFirst();
    }

    private static final RowMapper<LegacyUser> LEGACY_ROW_MAPPER = (rs, i) -> {
        LegacyUser u = new LegacyUser();
        u.setUsername(rs.getString("username"));
        u.setUserId(rs.getString("userid"));
        u.setRealName(rs.getString("real_name"));
        u.setWorkFor(rs.getString("work_for"));
        u.setEmail(rs.getString("email"));
        u.setMobile(rs.getString("mobile"));
        u.setCreatedFrom(rs.getString("created_from"));
        u.setEnabled(rs.getObject("enabled") == null ? false : rs.getInt("enabled") != 0);
        u.setLegacyPassword(rs.getString("password"));
        return u;
    };

    /** Reads our own credential-state row (new hash + upgrade flag), never the legacy table. */
    public Optional<UserCredentialState> findCredentialState(String username) {
        try {
            List<UserCredentialState> rows = jdbc.query(
                    "select username, password_hash, password_scheme, upgraded, updated_at "
                            + "from sso_user_credential where username = ?",
                    (rs, i) -> new UserCredentialState(
                            rs.getString("username"),
                            rs.getString("password_hash"),
                            rs.getString("password_scheme"),
                            rs.getBoolean("upgraded"),
                            rs.getTimestamp("updated_at") == null ? null
                                    : rs.getTimestamp("updated_at").toInstant()),
                    username);
            return rows.stream().findFirst();
        } catch (RuntimeException ex) {
            return Optional.empty();
        }
    }

    /**
     * Legacy comparison, verbatim: the submitted value is what the browser already MD5'd, so it is
     * compared as plain text against the stored column.
     */
    public boolean matchesLegacyPassword(String submittedAlreadyMd5, String storedValue) {
        return submittedAlreadyMd5 != null
                && storedValue != null
                && MessageDigest.isEqual(
                        submittedAlreadyMd5.getBytes(StandardCharsets.UTF_8),
                        storedValue.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Recomputes the browser-side digest server side, so a non-browser client that posts the raw
     * password (CLI, scripted login, our own form when {@code legacy-hash-in-frontend=false})
     * still authenticates. Uses the exact legacy recipe.
     */
    public static String legacyDigest(String rawPassword, String username) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] digest = md5.digest((rawPassword + "{" + username + "}").getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(32);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 unavailable", e);
        }
    }

    /**
     * Writes the new BCrypt hash plus the upgrade flag into <em>our own</em> table.
     *
     * <p>Called inside the authentication transaction together with the credential check, so a
     * successful login always leaves a consistent state.
     */
    @Transactional
    public void upgradePassword(String username, String rawPassword) {
        String hash = passwordEncoder.encode(rawPassword);
        upsertCredential(username, hash, "BCRYPT", true);
    }

    @Transactional
    public void upsertCredential(String username, String hash, String scheme, boolean upgraded) {
        int updated = jdbc.update(
                "update sso_user_credential set password_hash = ?, password_scheme = ?, upgraded = ?, updated_at = now() "
                        + "where username = ?",
                hash, scheme, upgraded, username);
        if (updated == 0) {
            jdbc.update(
                    "insert into sso_user_credential (username, password_hash, password_scheme, upgraded, updated_at) "
                            + "values (?, ?, ?, ?, now())",
                    username, hash, scheme, upgraded);
        }
    }

    /** Extension-table write: records the last successful login without touching the legacy table. */
    public void recordSuccessfulLogin(String username, String clientIp) {
        try {
            jdbc.update(
                    "insert into sso_login_audit (username, event, client_ip, occurred_at) values (?, 'LOGIN_SUCCESS', ?, now())",
                    username, clientIp);
        } catch (RuntimeException ignored) {
            // Audit must never break authentication.
        }
    }

    /** Extension-table write: records a failed attempt for the modern lock policy. */
    public void recordFailedLogin(String username, String clientIp, String reason) {
        try {
            jdbc.update(
                    "insert into sso_login_audit (username, event, client_ip, occurred_at) values (?, ?, ?, now())",
                    username, "LOGIN_FAILURE:" + reason, clientIp);
        } catch (RuntimeException ignored) {
            // Audit must never break authentication.
        }
    }

    /**
     * Counts recent failures from our own audit table so we can apply the architecture's lock policy
     * without reading the legacy {@code is_password_invalid} columns.
     */
    public int countRecentFailures(String username) {
        try {
            Integer n = jdbc.queryForObject(
                    "select count(*) from sso_login_audit "
                            + "where username = ? and event like 'LOGIN_FAILURE%' and occurred_at > now() - (? || ' seconds')::interval",
                    Integer.class, username, String.valueOf(props.getLegacy().getLockWindow().toSeconds()));
            return n == null ? 0 : n;
        } catch (RuntimeException ex) {
            return 0;
        }
    }

    /** Builds the principal attribute map consumed by {@link cn.geodata.sso.cas.attr.CasAttributeAssembler}. */
    public Map<String, Object> toPrincipalAttributes(LegacyUser u) {
        Map<String, Object> attrs = new LinkedHashMap<>();
        attrs.put(CasPrincipalAttributes.USERNAME, u.getUsername());
        attrs.put(CasPrincipalAttributes.USER_ID, u.getUserId());
        attrs.put(CasPrincipalAttributes.REAL_NAME, u.getRealName());
        attrs.put(CasPrincipalAttributes.WORK_FOR, u.getWorkFor());
        attrs.put(CasPrincipalAttributes.EMAIL, u.getEmail());
        attrs.put(CasPrincipalAttributes.MOBILE, u.getMobile());
        attrs.put(CasPrincipalAttributes.CREATED_FROM, u.getCreatedFrom());
        attrs.put(CasPrincipalAttributes.IS_ENABLED, u.isEnabled());
        return attrs;
    }

    public static class LegacyUser {

        private String username;
        private String userId;
        private String realName;
        private String workFor;
        private String email;
        private String mobile;
        private String createdFrom;
        private boolean enabled;
        private String legacyPassword;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public String getRealName() {
            return realName;
        }

        public void setRealName(String realName) {
            this.realName = realName;
        }

        public String getWorkFor() {
            return workFor;
        }

        public void setWorkFor(String workFor) {
            this.workFor = workFor;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getMobile() {
            return mobile;
        }

        public void setMobile(String mobile) {
            this.mobile = mobile;
        }

        public String getCreatedFrom() {
            return createdFrom;
        }

        public void setCreatedFrom(String createdFrom) {
            this.createdFrom = createdFrom;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getLegacyPassword() {
            return legacyPassword;
        }

        public void setLegacyPassword(String legacyPassword) {
            this.legacyPassword = legacyPassword;
        }
    }

    public record UserCredentialState(String username, String passwordHash, String passwordScheme,
                                      boolean upgraded, java.time.Instant updatedAt) {
    }
}
