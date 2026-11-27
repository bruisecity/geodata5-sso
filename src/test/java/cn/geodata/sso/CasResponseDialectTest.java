package cn.geodata.sso.cas.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.geodata.sso.cas.attr.CasAttributeAssembler;
import cn.geodata.sso.cas.attr.CasPrincipalAttributes;
import java.lang.reflect.Method;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Golden-sample snapshot tests for the legacy attribute dialect (architecture 5.2A).
 *
 * <p>The decisive assertions do not trust a hand-written imitation of the parser: they call
 * {@link Cas20ServiceTicketValidator#extractCustomAttributes} on the <em>real</em>
 * {@code cas-client-core:3.2.1} jar (the exact library the 存量 applications depend on, test-scope
 * dependency only). Two facts were established by disassembling that jar and are encoded here:
 *
 * <ol>
 *   <li>{@code extractCustomAttributes} takes the name as {@code line.substring(line.indexOf(":")+1,
 *       line.indexOf(">"))} - the <b>first</b> colon. A {@code <cas:userId>} line yields
 *       {@code "userId"}; an un-prefixed {@code <userId>} line yields {@code "<userId"}, which SAX
 *       will never match, so every attribute is silently lost.</li>
 *   <li>it reads the {@code <cas:attributes>} block with {@code BufferedReader.readLine()} and takes
 *       <b>one attribute name per line</b>. All attributes packed onto one line yields only the
 *       first one.</li>
 * </ol>
 *
 * <p><strong>Provenance caveat (tracked in docs/verification.md):</strong> the expected strings are
 * derived from the legacy JSP contract ({@code casServiceValidationSuccess.jsp:5-27},
 * {@code casServiceValidationFailure.jsp:22-26}) plus {@code deployerConfigContext.xml:81-93}. A
 * captured response from the running legacy server has NOT been supplied yet, so the snapshots are
 * reviewed against source and against the real client parser, not against a packet capture. When
 * the capture arrives it goes into {@code golden/legacy-servicevalidate-success.xml}.
 */
class CasResponseDialectTest {

    private CasAttributeAssembler assemblerWithoutDb() {
        // null JdbcTemplate -> the assembler falls back to the built-in contract (same eight names)
        return new CasAttributeAssembler(null, new cn.geodata.sso.config.SsoProperties());
    }

    private Map<String, Object> zhangsanAttributes() {
        Map<String, Object> attrs = new LinkedHashMap<>();
        attrs.put(CasPrincipalAttributes.USERNAME, "zhangsan");
        attrs.put(CasPrincipalAttributes.USER_ID, "1001");
        attrs.put(CasPrincipalAttributes.REAL_NAME, "张三");
        attrs.put(CasPrincipalAttributes.WORK_FOR, "地理信息中心");
        attrs.put(CasPrincipalAttributes.EMAIL, "zhangsan@geodata.cn");
        attrs.put(CasPrincipalAttributes.MOBILE, "13800000001");
        attrs.put(CasPrincipalAttributes.CREATED_FROM, "CAS");
        attrs.put(CasPrincipalAttributes.IS_ENABLED, true);
        return attrs;
    }

    /**
     * Calls the real client's protected parser. This is the whole point of the test: if the
     * production code regresses to un-prefixed or single-line attributes, these tests fail because
     * the actual legacy client stops seeing attributes.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> realClientParse(String xml) throws Exception {
        Cas20ServiceTicketValidator validator = new Cas20ServiceTicketValidator("http://localhost:9000/cas");
        Method m = Cas20ServiceTicketValidator.class
                .getDeclaredMethod("extractCustomAttributes", String.class);
        m.setAccessible(true);
        return (Map<String, Object>) m.invoke(validator, xml);
    }

    @Test
    @DisplayName("real cas-client-core 3.2.1 recovers all eight attributes from our response")
    void realLegacyClientRecoversAllEightAttributes() throws Exception {
        var assembler = assemblerWithoutDb();
        String xml = new CasResponseRenderer()
                .serviceValidationSuccess("zhangsan", assembler.assemble(zhangsanAttributes()));

        Map<String, Object> parsed = realClientParse(xml);

        assertEquals(8, parsed.size(), "the real legacy client must recover all eight attributes");
        // exact-casing contract: userId (capital I) and createdFrom/realName/workFor/isEnabled
        assertEquals("1001", parsed.get("userId"));
        assertEquals("张三", parsed.get("realName"));
        assertEquals("地理信息中心", parsed.get("workFor"));
        assertEquals("zhangsan@geodata.cn", parsed.get("email"));
        assertEquals("13800000001", parsed.get("mobile"));
        assertEquals("CAS", parsed.get("createdFrom"));
        assertEquals("true", parsed.get("isEnabled"));
        assertEquals("zhangsan", parsed.get("username"));
        assertFalse(parsed.containsKey("roleId"), "roleId is not emitted");
        assertFalse(parsed.containsKey("roleName"), "roleName is not emitted");
    }

    @Test
    @DisplayName("regression witness: un-prefixed single-line output loses every attribute")
    void unprefixedOrSingleLineOutputBreaksTheRealClient() throws Exception {
        // Exactly what the pre-fix renderer produced: no cas: prefix, all attributes on one line.
        String broken = "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>"
                + "<cas:authenticationSuccess><cas:user>zhangsan</cas:user><cas:attributes>"
                + "<userId>1001</userId><realName>张三</realName>"
                + "</cas:attributes></cas:authenticationSuccess></cas:serviceResponse>";

        Map<String, Object> parsed = realClientParse(broken);

        // one line -> the parser collects exactly one candidate name, and it is a malformed one
        assertEquals(1, parsed.size(),
                "a single-line block yields at most one candidate; the other attributes are lost");
        assertTrue(parsed.containsKey("<userId"),
                "without the cas: prefix the name is '<userId' (first colon is the namespace of "
                        + "nothing, so indexOf(':')+1 lands after 'cas' only when the prefix exists)");
        assertFalse(parsed.containsKey("userId"),
                "the client can never look up 'userId' from '<userId' -> attributes silently vanish");
    }

    @Test
    @DisplayName("success response uses the legacy dialect: cas:-prefixed element per attribute line")
    void successResponseUsesLegacyDialect() {
        var assembler = assemblerWithoutDb();
        List<Map.Entry<String, String>> attrs = assembler.assemble(zhangsanAttributes());

        // exactly the eight attributes, in legacy emission order, with legacy spelling
        assertEquals(List.of("username", "userId", "realName", "workFor", "email", "mobile",
                "createdFrom", "isEnabled"), attrs.stream().map(Map.Entry::getKey).toList());

        String xml = new CasResponseRenderer().serviceValidationSuccess("zhangsan", attrs);

        // element name IS the attribute key, prefixed with cas: - this is the contract
        assertTrue(xml.contains("<cas:userId>1001</cas:userId>"), "userId element must be literally <cas:userId>");
        assertTrue(xml.contains("<cas:realName>张三</cas:realName>"));
        assertTrue(xml.contains("<cas:isEnabled>true</cas:isEnabled>"), "default literal per T-16 is true/false");
        assertTrue(xml.contains("<cas:workFor>地理信息中心</cas:workFor>"));
        assertTrue(xml.contains("<cas:username>zhangsan</cas:username>"));
        assertTrue(xml.contains("<cas:createdFrom>CAS</cas:createdFrom>"));

        // the wrapping structure the official client splits on
        assertTrue(xml.startsWith("<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>"));
        assertTrue(xml.contains("<cas:authenticationSuccess><cas:user>zhangsan</cas:user><cas:attributes>"));
        assertTrue(xml.endsWith("</cas:authenticationSuccess></cas:serviceResponse>"));

        // anti-assertions: standard CAS 3.0 shape, un-prefixed elements, pre-revision example name
        assertFalse(xml.contains("<cas:name>"), "must not emit standard <cas:name> elements");
        assertFalse(xml.contains("<cas:value>"), "must not emit standard <cas:value> elements");
        assertFalse(xml.contains("displayName"), "example attribute from the pre-revision doc must be gone");
        assertFalse(xml.contains("\n<userId>"), "attributes must never be emitted without the cas: prefix");
    }

    @Test
    @DisplayName("roleId / roleName stay out of the response (commented out in legacy source)")
    void rolesAreNotEmitted() {
        var assembler = assemblerWithoutDb();
        String xml = new CasResponseRenderer()
                .serviceValidationSuccess("zhangsan", assembler.assemble(zhangsanAttributes()));
        assertFalse(xml.contains("roleId"));
        assertFalse(xml.contains("roleName"));
        // T-17: no tenant/roles/other new attributes either
        assertFalse(xml.contains("tenant"));
        assertFalse(xml.contains("<cas:roles>"));
    }

    @Test
    @DisplayName("isEnabled literal is configurable for T-16")
    void enabledLiteralIsConfigurable() {
        var props = new cn.geodata.sso.config.SsoProperties();
        props.getLegacy().setEnabledLiteral(cn.geodata.sso.config.SsoProperties.EnabledLiteral.ONE_ZERO);
        var assembler = new CasAttributeAssembler(null, props);
        List<Map.Entry<String, String>> attrs = assembler.assemble(zhangsanAttributes());
        String xml = new CasResponseRenderer().serviceValidationSuccess("zhangsan", attrs);
        assertTrue(xml.contains("<cas:isEnabled>1</cas:isEnabled>"));
    }

    @Test
    @DisplayName("failure response keeps the legacy wrapper and single-quoted code")
    void failureResponseMatchesLegacyTemplate() {
        String xml = new CasResponseRenderer()
                .serviceValidationFailure(CasFailureCode.INVALID_TICKET, "Ticket [ST-x] not recognized");
        assertEquals("<cas:serviceResponse><cas:authenticationFailure code='INVALID_TICKET'>"
                + "Ticket [ST-x] not recognized</cas:authenticationFailure></cas:serviceResponse>", xml);
        // the legacy failure view served text/plain, not XML
        assertTrue(CasResponseRenderer.FAILURE_CONTENT_TYPE.startsWith("text/plain"));
    }

    @Test
    @DisplayName("CAS 1.0 /validate bodies are yes\\nuser\\n and no\\n\\n")
    void validateBodies() {
        var r = new CasResponseRenderer();
        assertEquals("yes\nzhangsan\n", r.validateSuccess("zhangsan"));
        assertEquals("no\n\n", r.validateFailure());
    }

    @Test
    @DisplayName("attribute values are XML-escaped, so a name with & or < cannot break the document")
    void valuesAreEscaped() throws Exception {
        Map<String, Object> attrs = new LinkedHashMap<>();
        attrs.put(CasPrincipalAttributes.USERNAME, "a&b");
        attrs.put(CasPrincipalAttributes.REAL_NAME, "<script>");
        var assembler = assemblerWithoutDb();
        String xml = new CasResponseRenderer()
                .serviceValidationSuccess("a&b", assembler.assemble(attrs));
        assertTrue(xml.contains("a&amp;b"));
        assertTrue(xml.contains("&lt;script&gt;"));

        // and the escaping must still be a parseable document for the real client
        Map<String, Object> parsed = realClientParse(xml);
        assertEquals("a&b", parsed.get("username"), "escaped ampersand decodes back to &");
        assertEquals("<script>", parsed.get("realName"), "escaped angle brackets decode back to <script>");
    }
}
