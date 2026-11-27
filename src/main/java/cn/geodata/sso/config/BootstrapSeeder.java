package cn.geodata.sso.config;

import cn.geodata.sso.user.LegacyUserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.ApplicationArguments;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

/**
 * Idempotent seed for the local profile: registered clients plus two users.
 *
 * <p>Two users are deliberate and each proves a distinct path:
 * <ul>
 *   <li>{@code zhangsan} - seeded with an <em>already-upgraded</em> BCrypt credential, i.e. the
 *       steady-state modern flow.</li>
 *   <li>{@code legacy_user} - seeded with a raw password in YAML but written to the legacy column
 *       only as {@code hex_md5(pw + "{username}")}, exactly what the old browser would have stored.
 *       This exercises the legacy comparison and the upgrade-in-the-same-transaction behaviour.</li>
 * </ul>
 *
 * <p>Seeding is idempotent: existing clients are skipped by {@code client_id}, existing users by
 * primary key, so restarting the app never duplicates rows.
 */
@Component
public class BootstrapSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BootstrapSeeder.class);

    private final SsoProperties props;
    private final RegisteredClientRepository clients;
    private final JdbcTemplate jdbc;
    private final LegacyUserRepository users;
    private final org.springframework.security.crypto.password.PasswordEncoder encoder;

    public BootstrapSeeder(SsoProperties props, RegisteredClientRepository clients, JdbcTemplate jdbc,
                           LegacyUserRepository users,
                           org.springframework.security.crypto.password.PasswordEncoder encoder) {
        this.props = props;
        this.clients = clients;
        this.jdbc = jdbc;
        this.users = users;
        this.encoder = encoder;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!props.getBootstrap().isSeed()) {
            return;
        }
        seedClients();
        seedUsers();
    }

    private void seedClients() {
        for (SsoProperties.Bootstrap.SeedClient seed : props.getBootstrap().getClients()) {
            if (clients.findByClientId(seed.getClientId()) != null) {
                log.info("seed client already present: {}", seed.getClientId());
                continue;
            }
            RegisteredClient rc = AuthorizationServerConfig.buildClient(seed);
            clients.save(rc);
            log.info("seeded OAuth client {} (public={}, redirectUris={})",
                    seed.getClientId(), seed.isPublicClient(), seed.getRedirectUris());
        }
    }

    private void seedUsers() {
        for (SsoProperties.Bootstrap.SeedUser seed : props.getBootstrap().getUsers()) {
            int existing = jdbc.queryForObject(
                    "select count(*) from t_customer where username = ?", Integer.class, seed.getUsername());
            if (existing > 0) {
                log.info("seed user already present: {}", seed.getUsername());
                continue;
            }

            boolean hasRaw = seed.getPassword() != null && !seed.getPassword().isBlank();
            String legacyColumnValue;
            if (seed.getLegacyPassword() != null) {
                legacyColumnValue = seed.getLegacyPassword();
            } else if (hasRaw) {
                // Reproduce the exact value the legacy browser produced:
                // hex_md5(rawPassword + "{" + username + "}").
                legacyColumnValue = LegacyUserRepository.legacyDigest(seed.getPassword(), seed.getUsername());
            } else {
                legacyColumnValue = "";
            }

            jdbc.update("insert into t_customer "
                            + "(username, userid, real_name, work_for, email, mobile, created_from, enabled, password) "
                            + "values (?,?,?,?,?,?,?,?,?)",
                    seed.getUsername(), seed.getUserId(), seed.getRealName(), seed.getWorkFor(),
                    seed.getEmail(), seed.getMobile(), seed.getCreatedFrom(),
                    seed.isEnabled() ? 1 : 0, legacyColumnValue);

            if (hasRaw) {
                // zhangsan: modern path from the start. legacy_user is intentionally left without a
                // BCrypt row so the legacy branch is actually exercised.
                if (seed.getLegacyPassword() == null && !"legacy_user".equals(seed.getUsername())) {
                    users.upsertCredential(seed.getUsername(), encoder.encode(seed.getPassword()), "BCRYPT", true);
                }
            }
            log.info("seeded user {} (createdFrom={}, legacy column={})", seed.getUsername(),
                    seed.getCreatedFrom(), legacyColumnValue);
        }
    }
}
