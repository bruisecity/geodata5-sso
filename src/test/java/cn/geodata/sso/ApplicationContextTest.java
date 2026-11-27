package cn.geodata.sso;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.geodata.sso.cas.attr.CasAttributeAssembler;
import cn.geodata.sso.user.LegacyUserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

/**
 * Proves the whole wiring boots: three filter chains, JDBC repositories, seeded clients and users,
 * and the attribute mapping table loaded from SQL rather than from code.
 */
@SpringBootTest
@ActiveProfiles("test")
class ApplicationContextTest {

    @Autowired
    private ApplicationContext context;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private CasAttributeAssembler assembler;

    @Autowired
    private LegacyUserRepository users;

    @Test
    @DisplayName("context loads and all three security chains are registered")
    void contextsWired() {
        assertNotNull(context.getBean(
                org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings.class));
        assertNotNull(context.getBean(
                org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository.class));
        assertTrue(context.getBeansOfType(org.springframework.security.web.SecurityFilterChain.class).size() >= 3,
                "authorization-server, cas and application chains must all be present");
    }

    @Test
    @DisplayName("seeded clients exist and the public SPA client requires PKCE")
    void seededClients() {
        var repo = context.getBean(
                org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository.class);
        var web = repo.findByClientId("demo-web");
        assertNotNull(web, "demo-web must be seeded");
        var spa = repo.findByClientId("demo-spa");
        assertNotNull(spa, "demo-spa must be seeded");
        assertTrue(spa.getClientSettings().isRequireProofKey(),
                "public client must require PKCE (architecture 10.1)");
        assertEquals(true, spa.getClientAuthenticationMethods().stream()
                .anyMatch(m -> m.getValue().equals("none")), "public client has no client secret");
    }

    @Test
    @DisplayName("attribute mapping is read from cas_attribute_mapping, eight emitted rows")
    void mappingTableDrivesAttributes() {
        int emitted = jdbc.queryForObject(
                "select count(*) from cas_attribute_mapping where emitted = true", Integer.class);
        int notEmitted = jdbc.queryForObject(
                "select count(*) from cas_attribute_mapping where emitted = false", Integer.class);
        assertEquals(8, emitted, "exactly eight attributes are exported");
        assertEquals(2, notEmitted, "roleId/roleName exist as rows but are not exported");
        assertEquals(8, assembler.loadMappings().stream().filter(m -> m.emitted()).count());
    }

    @Test
    @DisplayName("legacy seed stores exactly hex_md5(password{username}), not the raw password")
    void legacySeedUsesLegacyDigest() {
        String stored = jdbc.queryForObject(
                "select password from t_customer where username = 'legacy_user'", String.class);
        assertEquals(LegacyUserRepository.legacyDigest("legacy123", "legacy_user"), stored);
        // and it must be a 32-char lowercase hex digest
        assertEquals(32, stored.length());
        assertTrue(stored.matches("[0-9a-f]{32}"));
    }

    @Test
    @DisplayName("legacy_user has no BCrypt row yet, so the legacy branch is genuinely exercised")
    void legacyUserNotYetUpgraded() {
        assertTrue(users.findCredentialState("legacy_user").isEmpty());
        assertTrue(users.findCredentialState("zhangsan").isPresent(), "zhangsan starts on the BCrypt path");
    }
}
