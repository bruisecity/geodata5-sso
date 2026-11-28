package cn.geodata.sso.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * All tunables of the SSO service.
 *
 * <p>Design rule taken from the architecture doc (revision 28, section 5.2C / 5.2B / 5.3):
 * anything the legacy source code pins down as a hard protocol fact is a <em>default</em> here,
 * never a hard-coded constant in the code, because the remaining open questions (T-14 mounting
 * path, T-16 {@code enabled} literal, T-13 registry mode) must be answerable by configuration
 * change only.
 */
@ConfigurationProperties(prefix = "sso")
public class SsoProperties {

    /** Public base URL of this server, used for issuer and for building ticket redirects. */
    private String issuer = "http://localhost:9000";

    private final Cas cas = new Cas();
    private final Legacy legacy = new Legacy();
    private final Security security = new Security();
    private final Bootstrap bootstrap = new Bootstrap();

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public Cas getCas() {
        return cas;
    }

    public Legacy getLegacy() {
        return legacy;
    }

    public Security getSecurity() {
        return security;
    }

    public Bootstrap getBootstrap() {
        return bootstrap;
    }

    // ---------------------------------------------------------------------------------------
    // CAS compatibility layer
    // ---------------------------------------------------------------------------------------
    public static class Cas {

        /**
         * Mount prefixes the CAS endpoints answer on.
         *
         * <p>Section 5.2C: the legacy server claims {@code server.prefix=${server.name}/cas} while
         * every legacy client is configured with the bare root ({@code http://auth.geodata.cn/login}).
         * Both must work until T-14 is answered, so both prefixes are exposed.
         */
        private List<String> mountPaths = new ArrayList<>(List.of("/cas", ""));

        /** {@code CASTGC} cookie path; must cover whichever prefix clients actually hit (T-14). */
        private String ticketCookiePath = "/";

        private String ticketCookieName = "CASTGC";

        /**
         * Section 5.2B: legacy ran an empty in-memory registry with a forced authorization check,
         * which would deny every service-bearing login. We refuse to copy that. Default is lenient.
         */
        private ServiceRegistryMode serviceRegistryMode = ServiceRegistryMode.LENIENT;

        /** Legacy {@code Session} timeout was 60 minutes (web.xml) - independent of the TGT TTL. */
        private Duration sessionTimeout = Duration.ofMinutes(60);

        /** Legacy ST policy: 1 use AND 10 seconds (MultiTimeUseOrTimeoutExpirationPolicy). */
        private Duration serviceTicketTtl = Duration.ofSeconds(10);

        /** Legacy TGT: maxTimeToLive 8h, timeToKill 2h (ticketExpirationPolicies.xml:44-46). */
        private Duration ticketGrantingTicketMaxLifetime = Duration.ofHours(8);

        private Duration ticketGrantingTicketIdleTimeout = Duration.ofHours(2);

        /** Legacy login page fields: username / password / yzm / lt / execution / _eventId. */
        private final LoginPage loginPage = new LoginPage();

        /** Legacy {@code protocol_views.properties} hard-coded issuer {@code localhost}. */


        /** Legacy {@code /cas/captcha.jpg} via {@code com.nauth.ImageCaptchaServlet}. */
        private final Captcha captcha = new Captcha();

        public List<String> getMountPaths() {
            return mountPaths;
        }

        public void setMountPaths(List<String> mountPaths) {
            this.mountPaths = mountPaths;
        }

        public String getTicketCookiePath() {
            return ticketCookiePath;
        }

        public void setTicketCookiePath(String ticketCookiePath) {
            this.ticketCookiePath = ticketCookiePath;
        }

        public String getTicketCookieName() {
            return ticketCookieName;
        }

        public void setTicketCookieName(String ticketCookieName) {
            this.ticketCookieName = ticketCookieName;
        }

        public ServiceRegistryMode getServiceRegistryMode() {
            return serviceRegistryMode;
        }

        public void setServiceRegistryMode(ServiceRegistryMode serviceRegistryMode) {
            this.serviceRegistryMode = serviceRegistryMode;
        }

        public Duration getSessionTimeout() {
            return sessionTimeout;
        }

        public void setSessionTimeout(Duration sessionTimeout) {
            this.sessionTimeout = sessionTimeout;
        }

        public Duration getServiceTicketTtl() {
            return serviceTicketTtl;
        }

        public void setServiceTicketTtl(Duration serviceTicketTtl) {
            this.serviceTicketTtl = serviceTicketTtl;
        }

        public Duration getTicketGrantingTicketMaxLifetime() {
            return ticketGrantingTicketMaxLifetime;
        }

        public void setTicketGrantingTicketMaxLifetime(Duration ticketGrantingTicketMaxLifetime) {
            this.ticketGrantingTicketMaxLifetime = ticketGrantingTicketMaxLifetime;
        }

        public Duration getTicketGrantingTicketIdleTimeout() {
            return ticketGrantingTicketIdleTimeout;
        }

        public void setTicketGrantingTicketIdleTimeout(Duration ticketGrantingTicketIdleTimeout) {
            this.ticketGrantingTicketIdleTimeout = ticketGrantingTicketIdleTimeout;
        }

        public LoginPage getLoginPage() {
            return loginPage;
        }





        public Captcha getCaptcha() {
            return captcha;
        }

        public static class LoginPage {

            /**
             * Legacy flow forced a captcha before {@code realSubmit} (login-webflow.xml).
             * Kept as a config switch because a captcha cannot be delivered without the
             * legacy {@code com.nauth.ImageCaptchaServlet} tuning; see docs/verification.md.
             */
            private boolean captchaRequired = true;

            /** Auto-answer the captcha in non-prod so scripted smoke tests can log in. */
            private boolean captchaBypassForLocalProfile = true;

            private String formAction = "/login";

            public boolean isCaptchaRequired() {
                return captchaRequired;
            }

            public void setCaptchaRequired(boolean captchaRequired) {
                this.captchaRequired = captchaRequired;
            }

            public boolean isCaptchaBypassForLocalProfile() {
                return captchaBypassForLocalProfile;
            }

            public void setCaptchaBypassForLocalProfile(boolean captchaBypassForLocalProfile) {
                this.captchaBypassForLocalProfile = captchaBypassForLocalProfile;
            }

            public String getFormAction() {
                return formAction;
            }

            public void setFormAction(String formAction) {
                this.formAction = formAction;
            }
        }

        public static class Captcha {

            private int width = 100;

            private int height = 30;

            private int length = 4;

            private Duration ttl = Duration.ofMinutes(5);

            public int getWidth() {
                return width;
            }

            public void setWidth(int width) {
                this.width = width;
            }

            public int getHeight() {
                return height;
            }

            public void setHeight(int height) {
                this.height = height;
            }

            public int getLength() {
                return length;
            }

            public void setLength(int length) {
                this.length = length;
            }

            public Duration getTtl() {
                return ttl;
            }

            public void setTtl(Duration ttl) {
                this.ttl = ttl;
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Legacy user store (section 5.7.4, strategy S1: same-database read-only sharing)
    // ---------------------------------------------------------------------------------------
    public static class Legacy {

        private boolean enabled = true;

        /**
         * Section 5.7.2 / 5.7.3: legacy authentication reads
         * {@code select password from t_customer where username=? and enabled=1 and created_from='CAS'}.
         * Table and column names stay configurable so the DBA-exported DDL (T-18) can be matched
         * without touching code.
         */
        private String table = "t_customer";

        private String usernameColumn = "username";

        private String passwordColumn = "password";

        private String userIdColumn = "userid";

        private String realNameColumn = "real_name";

        private String workForColumn = "work_for";

        private String emailColumn = "email";

        private String mobileColumn = "mobile";

        private String createdFromColumn = "created_from";

        private String enabledColumn = "enabled";

        /**
         * Legacy auth SQL pinned {@code created_from='CAS'} as a filter. Our own local seed users
         * carry {@code LOCAL}, so the filter value is configurable and the seeds are visible in the
         * local profile. In prod it should stay {@code CAS} to match the legacy statement.
         */
        private String createdFromFilter = "CAS";

        /**
         * Section 5.7.3: password value in the legacy column is
         * {@code hex_md5(pw + "{" + username + "}")}, compared as plain text by
         * {@code MyQueryDatabaseAuthenticationHandler}. We reproduce exactly that comparison.
         */
        private String legacyPasswordScheme = "LEGACY_HEX_MD5_OF_PASSWORD_BRACED_USERNAME";

        /**
         * Section 5.7.3: on a successful legacy login the new BCrypt hash is written
         * in the same transaction and the upgrade flag is flipped, so the next login
         * takes the new path.
         */
        private boolean upgradePasswordOnLogin = true;

        /** Section 5.7.2: legacy {@code enabled} is 1/0. T-16 says the XML literal is unconfirmed. */
        private EnabledLiteral enabledLiteral = EnabledLiteral.TRUE_FALSE;

        /**
         * Section 5.7.4: any write (login counter, lock flag, last-login time) must go to our own
         * extension tables, never back to {@code t_customer}, or it fights the legacy lock logic.
         */
        private boolean readOnlySourceOfTruth = true;

        /** Legacy lock: 5 failures within 30 minutes locks for 30 minutes (handler lines 88-105). */
        private int lockThreshold = 5;

        private Duration lockWindow = Duration.ofMinutes(30);

        private Duration lockDuration = Duration.ofMinutes(30);

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getTable() {
            return table;
        }

        public void setTable(String table) {
            this.table = table;
        }

        public String getUsernameColumn() {
            return usernameColumn;
        }

        public void setUsernameColumn(String usernameColumn) {
            this.usernameColumn = usernameColumn;
        }

        public String getPasswordColumn() {
            return passwordColumn;
        }

        public void setPasswordColumn(String passwordColumn) {
            this.passwordColumn = passwordColumn;
        }

        public String getUserIdColumn() {
            return userIdColumn;
        }

        public void setUserIdColumn(String userIdColumn) {
            this.userIdColumn = userIdColumn;
        }

        public String getRealNameColumn() {
            return realNameColumn;
        }

        public void setRealNameColumn(String realNameColumn) {
            this.realNameColumn = realNameColumn;
        }

        public String getWorkForColumn() {
            return workForColumn;
        }

        public void setWorkForColumn(String workForColumn) {
            this.workForColumn = workForColumn;
        }

        public String getEmailColumn() {
            return emailColumn;
        }

        public void setEmailColumn(String emailColumn) {
            this.emailColumn = emailColumn;
        }

        public String getMobileColumn() {
            return mobileColumn;
        }

        public void setMobileColumn(String mobileColumn) {
            this.mobileColumn = mobileColumn;
        }

        public String getCreatedFromColumn() {
            return createdFromColumn;
        }

        public void setCreatedFromColumn(String createdFromColumn) {
            this.createdFromColumn = createdFromColumn;
        }

        public String getEnabledColumn() {
            return enabledColumn;
        }

        public void setEnabledColumn(String enabledColumn) {
            this.enabledColumn = enabledColumn;
        }

        public String getCreatedFromFilter() {
            return createdFromFilter;
        }

        public void setCreatedFromFilter(String createdFromFilter) {
            this.createdFromFilter = createdFromFilter;
        }

        public String getLegacyPasswordScheme() {
            return legacyPasswordScheme;
        }

        public void setLegacyPasswordScheme(String legacyPasswordScheme) {
            this.legacyPasswordScheme = legacyPasswordScheme;
        }

        public boolean isUpgradePasswordOnLogin() {
            return upgradePasswordOnLogin;
        }

        public void setUpgradePasswordOnLogin(boolean upgradePasswordOnLogin) {
            this.upgradePasswordOnLogin = upgradePasswordOnLogin;
        }

        public EnabledLiteral getEnabledLiteral() {
            return enabledLiteral;
        }

        public void setEnabledLiteral(EnabledLiteral enabledLiteral) {
            this.enabledLiteral = enabledLiteral;
        }

        public boolean isReadOnlySourceOfTruth() {
            return readOnlySourceOfTruth;
        }

        public void setReadOnlySourceOfTruth(boolean readOnlySourceOfTruth) {
            this.readOnlySourceOfTruth = readOnlySourceOfTruth;
        }

        public int getLockThreshold() {
            return lockThreshold;
        }

        public void setLockThreshold(int lockThreshold) {
            this.lockThreshold = lockThreshold;
        }

        public Duration getLockWindow() {
            return lockWindow;
        }

        public void setLockWindow(Duration lockWindow) {
            this.lockWindow = lockWindow;
        }

        public Duration getLockDuration() {
            return lockDuration;
        }

        public void setLockDuration(Duration lockDuration) {
            this.lockDuration = lockDuration;
        }
    }

    // ---------------------------------------------------------------------------------------
    // Security knobs
    // ---------------------------------------------------------------------------------------
    public static class Security {

        private boolean requireCaptchaForFormLogin = false;

        /** Public clients must use PKCE (architecture 10.1). */
        private boolean enforcePkceForPublicClients = true;

        private Duration accessTokenTtl = Duration.ofMinutes(30);

        private Duration refreshTokenTtl = Duration.ofDays(30);

        public boolean isRequireCaptchaForFormLogin() {
            return requireCaptchaForFormLogin;
        }

        public void setRequireCaptchaForFormLogin(boolean requireCaptchaForFormLogin) {
            this.requireCaptchaForFormLogin = requireCaptchaForFormLogin;
        }

        public boolean isEnforcePkceForPublicClients() {
            return enforcePkceForPublicClients;
        }

        public void setEnforcePkceForPublicClients(boolean enforcePkceForPublicClients) {
            this.enforcePkceForPublicClients = enforcePkceForPublicClients;
        }

        public Duration getAccessTokenTtl() {
            return accessTokenTtl;
        }

        public void setAccessTokenTtl(Duration accessTokenTtl) {
            this.accessTokenTtl = accessTokenTtl;
        }

        public Duration getRefreshTokenTtl() {
            return refreshTokenTtl;
        }

        public void setRefreshTokenTtl(Duration refreshTokenTtl) {
            this.refreshTokenTtl = refreshTokenTtl;
        }
    }

    // ---------------------------------------------------------------------------------------
    // Seed data (local profile only)
    // ---------------------------------------------------------------------------------------
    public static class Bootstrap {

        private boolean seed = false;

        private List<SeedClient> clients = new ArrayList<>();

        private List<SeedUser> users = new ArrayList<>();

        public boolean isSeed() {
            return seed;
        }

        public void setSeed(boolean seed) {
            this.seed = seed;
        }

        public List<SeedClient> getClients() {
            return clients;
        }

        public void setClients(List<SeedClient> clients) {
            this.clients = clients;
        }

        public List<SeedUser> getUsers() {
            return users;
        }

        public void setUsers(List<SeedUser> users) {
            this.users = users;
        }

        public static class SeedClient {

            private String clientId;

            private String clientSecret;

            private String clientName;

            private List<String> redirectUris = new ArrayList<>();

            private List<String> scopes = new ArrayList<>();

            private boolean publicClient = false;

            private String actorType = "USER";

            public String getClientId() {
                return clientId;
            }

            public void setClientId(String clientId) {
                this.clientId = clientId;
            }

            public String getClientSecret() {
                return clientSecret;
            }

            public void setClientSecret(String clientSecret) {
                this.clientSecret = clientSecret;
            }

            public String getClientName() {
                return clientName;
            }

            public void setClientName(String clientName) {
                this.clientName = clientName;
            }

            public List<String> getRedirectUris() {
                return redirectUris;
            }

            public void setRedirectUris(List<String> redirectUris) {
                this.redirectUris = redirectUris;
            }

            public List<String> getScopes() {
                return scopes;
            }

            public void setScopes(List<String> scopes) {
                this.scopes = scopes;
            }

            public boolean isPublicClient() {
                return publicClient;
            }

            public void setPublicClient(boolean publicClient) {
                this.publicClient = publicClient;
            }

            public String getActorType() {
                return actorType;
            }

            public void setActorType(String actorType) {
                this.actorType = actorType;
            }
        }

        public static class SeedUser {

            private String username;

            private String password;

            /** Legacy MD5-of-braced-username form, as stored in {@code t_customer.password}. */
            private String legacyPassword;

            private String userId;

            private String realName;

            private String workFor;

            private String email;

            private String mobile;

            private String createdFrom = "LOCAL";

            private boolean enabled = true;

            public String getUsername() {
                return username;
            }

            public void setUsername(String username) {
                this.username = username;
            }

            public String getPassword() {
                return password;
            }

            public void setPassword(String password) {
                this.password = password;
            }

            public String getLegacyPassword() {
                return legacyPassword;
            }

            public void setLegacyPassword(String legacyPassword) {
                this.legacyPassword = legacyPassword;
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
        }
    }

    /** Section 5.2B: legacy ran an empty registry with a forced check - we do not copy that. */
    public enum ServiceRegistryMode {
        /** Any non-empty {@code service} is allowed; the ticket is still validated. Matches legacy reality. */
        LENIENT,
        /** Only services present and enabled in {@code cas_service_registry} are allowed. */
        STRICT
    }

    /** Section 5.7.2 / T-16: {@code enabled} literal in the XML attribute dialect. */
    public enum EnabledLiteral {
        TRUE_FALSE,
        ONE_ZERO
    }

    /** Placeholder-friendly view of the attribute contract, used by docs and the mapping loader. */
    public Map<String, String> flatDefaults() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("sso.cas.mount-paths", String.join(",", cas.getMountPaths()));
        m.put("sso.cas.ticket-cookie-path", cas.getTicketCookiePath());
        m.put("sso.cas.service-registry-mode", cas.getServiceRegistryMode().name());
        m.put("sso.cas.service-ticket-ttl", cas.getServiceTicketTtl().toString());
        m.put("sso.cas.tgt-max-lifetime", cas.getTicketGrantingTicketMaxLifetime().toString());
        m.put("sso.cas.tgt-idle-timeout", cas.getTicketGrantingTicketIdleTimeout().toString());
        m.put("sso.legacy.enabled-literal", legacy.getEnabledLiteral().name());
        m.put("sso.legacy.created-from-filter", legacy.getCreatedFromFilter());
        return m;
    }
}
