package cn.geodata.sso.cas.attr;

import cn.geodata.sso.config.SsoProperties;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Builds the CAS response attribute set from a table, not from hard-coded code.
 *
 * <p>Architecture doc section 5.7.2 is explicit: the eight attribute names must not change, but
 * "某个老客户端按名取值" and "属性名需要临时调整" must never turn into a code change. Therefore
 * the source-column → element-name → emitted? → order mapping lives in {@code cas_attribute_mapping}.
 *
 * <p>The legacy names come from {@code deployerConfigContext.xml:81-93}
 * ({@code resultAttributeMapping}); {@code role_id}/{@code role_name} were commented out there,
 * so they are rows with {@code emitted=false} - present in the table, absent from the XML.
 */
@Component
public class CasAttributeAssembler {

    /** Canonical legacy names, verbatim incl. camel case ({@code userId} has a capital I). */
    public static final String USERNAME = "username";
    public static final String USER_ID = "userId";
    public static final String REAL_NAME = "realName";
    public static final String WORK_FOR = "workFor";
    public static final String EMAIL = "email";
    public static final String MOBILE = "mobile";
    public static final String CREATED_FROM = "createdFrom";
    public static final String IS_ENABLED = "isEnabled";

    private final JdbcTemplate jdbc;
    private final SsoProperties props;

    public CasAttributeAssembler(JdbcTemplate jdbc, SsoProperties props) {
        this.jdbc = jdbc;
        this.props = props;
    }

    /**
     * @param principal attributes of the authenticated principal (internal names, see
     *                  {@link CasPrincipalAttributes})
     * @return ordered list of (element name -> text value) exactly as the legacy JSP would emit
     */
    public List<Map.Entry<String, String>> assemble(Map<String, Object> principal) {
        List<CasAttributeMapping> mappings = loadMappings();
        List<Map.Entry<String, String>> out = new ArrayList<>(mappings.size());
        for (CasAttributeMapping m : mappings) {
            if (!m.emitted()) {
                continue;
            }
            Object raw = principal.get(m.sourceKey());
            String text = render(m.attributeName(), raw);
            if (text != null) {
                out.add(Map.entry(m.attributeName(), text));
            }
        }
        return out;
    }

    /** Convenience for tests and templates: name -> value map preserving insertion order. */
    public Map<String, String> assembleAsMap(Map<String, Object> principal) {
        Map<String, String> m = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : assemble(principal)) {
            m.put(e.getKey(), e.getValue());
        }
        return m;
    }

    /**
     * T-16: the legacy {@code enabled} column is an integer 1/0 but the XML literal produced by the
     * attribute DAO was never pinned down in source. Default per architecture is {@code true/false};
     * switch to {@code 1/0} by config once the real response is captured.
     */
    String render(String attributeName, Object raw) {
        if (raw == null) {
            return null;
        }
        if (IS_ENABLED.equals(attributeName)) {
            boolean b = asBoolean(raw);
            return props.getLegacy().getEnabledLiteral() == SsoProperties.EnabledLiteral.ONE_ZERO
                    ? (b ? "1" : "0")
                    : Boolean.toString(b);
        }
        if (raw instanceof Boolean b) {
            return Boolean.toString(b);
        }
        return raw.toString();
    }

    private boolean asBoolean(Object raw) {
        if (raw instanceof Boolean b) {
            return b;
        }
        if (raw instanceof Number n) {
            return n.intValue() != 0;
        }
        String s = raw.toString().trim();
        return "1".equals(s) || "true".equalsIgnoreCase(s) || "t".equalsIgnoreCase(s) || "yes".equalsIgnoreCase(s);
    }

    /**
     * Loads the mapping table; falls back to the source-code contract when the table is absent or
     * empty so the service still boots against a database that has not been migrated yet.
     */
    public List<CasAttributeMapping> loadMappings() {
        try {
            List<CasAttributeMapping> rows = jdbc.query(
                    "select attribute_name, source_key, emitted, sort_order from cas_attribute_mapping order by sort_order",
                    (rs, i) -> new CasAttributeMapping(
                            rs.getString("attribute_name"),
                            rs.getString("source_key"),
                            rs.getBoolean("emitted"),
                            rs.getInt("sort_order")));
            if (!rows.isEmpty()) {
                return rows;
            }
        } catch (RuntimeException ignored) {
            // Table missing (fresh DB, local profile before migration): use the built-in contract.
        }
        return defaults();
    }

    /**
     * The eight attributes from architecture section 5.7.2, in legacy emission order, plus the two
     * commented-out role rows which are explicitly NOT emitted (T-17: no new attributes in phase 1).
     */
    public static List<CasAttributeMapping> defaults() {
        List<CasAttributeMapping> list = new ArrayList<>();
        list.add(new CasAttributeMapping(USERNAME, CasPrincipalAttributes.USERNAME, true, 1));
        list.add(new CasAttributeMapping(USER_ID, CasPrincipalAttributes.USER_ID, true, 2));
        list.add(new CasAttributeMapping(REAL_NAME, CasPrincipalAttributes.REAL_NAME, true, 3));
        list.add(new CasAttributeMapping(WORK_FOR, CasPrincipalAttributes.WORK_FOR, true, 4));
        list.add(new CasAttributeMapping(EMAIL, CasPrincipalAttributes.EMAIL, true, 5));
        list.add(new CasAttributeMapping(MOBILE, CasPrincipalAttributes.MOBILE, true, 6));
        list.add(new CasAttributeMapping(CREATED_FROM, CasPrincipalAttributes.CREATED_FROM, true, 7));
        // Golden capture (user-supplied 2026-11-27): the running legacy server emits SEVEN attributes
        // and isEnabled is NOT among them. Row kept for traceability, emitted=false until the legacy
        // side confirms otherwise.
        list.add(new CasAttributeMapping(IS_ENABLED, CasPrincipalAttributes.IS_ENABLED, false, 8));
        // legacy source commented these out -> rows exist but are not emitted
        list.add(new CasAttributeMapping("roleId", CasPrincipalAttributes.ROLE_ID, false, 9));
        list.add(new CasAttributeMapping("roleName", CasPrincipalAttributes.ROLE_NAME, false, 10));
        return list;
    }

    public record CasAttributeMapping(String attributeName, String sourceKey, boolean emitted, int sortOrder) {
    }
}
