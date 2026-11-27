package cn.geodata.sso.cas.protocol;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Renders the legacy CAS responses <strong>verbatim</strong>, including the non-standard attribute
 * dialect.
 *
 * <p>Evidence (architecture 5.2A):
 * <ul>
 *   <li>Success template {@code casServiceValidationSuccess.jsp:5-27} emits
 *       {@code <cas:attributes>} whose <em>child element names are the attribute keys</em>
 *       ({@code <cas:userId>1001</cas:userId>}) - there is no {@code <cas:name>/<cas:value>} pair.</li>
 *   <li>{@code cas-client-core-3.2.1}'s {@code Cas20ServiceTicketValidator} splits on
 *       {@code <cas:attributes>} / {@code </cas:attributes>} / {@code :} / {@code >}, so the official
 *       client <em>depends</em> on this dialect. Emitting standard CAS 3.0 XML would make every
 *       legacy client silently receive zero attributes.</li>
 *   <li>Failure template {@code casServiceValidationFailure.jsp:22-26} returns
 *       {@code text/plain} carrying {@code <cas:authenticationFailure code='...'>}, still wrapped in
 *       {@code <cas:serviceResponse>}.</li>
 * </ul>
 *
 * <p>Note the legacy failure template uses no {@code xmlns} declaration and single quotes around the
 * code attribute; both are reproduced here because strict string-matching clients exist.
 */
@Component
public class CasResponseRenderer {

    /** Legacy namespace declared by the success template. */
    public static final String CAS_NAMESPACE = "http://www.yale.edu/tp/cas";

    /**
     * Prefix carried by every element inside {@code <cas:attributes>}.
     *
     * <p>Source: {@code casServiceValidationSuccess.jsp:5-27} writes {@code <cas:userId>} etc.,
     * because the JSP declares the {@code cas} prefix once on {@code <cas:serviceResponse>} and
     * reuses it for child elements. The official client splits on {@code ":"} and {@code ">"} after
     * {@code <cas:attributes>}, so an un-prefixed {@code <userId>} element yields the key
     * {@code "userId"} while a prefixed one yields the same key minus the prefix - which is exactly
     * what {@code Cas20ServiceTicketValidator} expects. Emitting the prefix is therefore required,
     * not cosmetic.
     */
    public static final String ATTRIBUTE_ELEMENT_PREFIX = "cas:";

    /**
     * Success response.
     *
     * @param username the {@code principal.id} the legacy server put in {@code <cas:user>}
     * @param attributes ordered attribute name -> value pairs (element names already resolved)
     */
    public String serviceValidationSuccess(String username, List<Map.Entry<String, String>> attributes) {
        StringBuilder sb = new StringBuilder(256);
        sb.append("<cas:serviceResponse xmlns:cas='").append(CAS_NAMESPACE).append("'>");
        sb.append("<cas:authenticationSuccess>");
        sb.append("<cas:user>").append(escape(username)).append("</cas:user>");
        if (attributes != null && !attributes.isEmpty()) {
            sb.append("<cas:attributes>");
            for (Map.Entry<String, String> attr : attributes) {
                // element name == attribute key, prefixed with "cas:" exactly as the legacy JSP did.
                // The newline before every element is NOT cosmetic: the official client
                // (Cas20ServiceTicketValidator#extractCustomAttributes, verified by disassembling
                // cas-client-core 3.2.1) reads the block line by line and takes ONE attribute name
                // per line. Emitting them on a single line loses every attribute but the first.
                String element = ATTRIBUTE_ELEMENT_PREFIX + attr.getKey();
                sb.append('\n').append('<').append(element).append('>')
                        .append(escape(attr.getValue()))
                        .append("</").append(element).append('>');
            }
            sb.append('\n').append("</cas:attributes>");
        }
        sb.append("</cas:authenticationSuccess>");
        sb.append("</cas:serviceResponse>");
        return sb.toString();
    }

    /**
     * Failure response.
     *
     * @param code one of {@link CasFailureCode}; the legacy server sent whatever the validation
     *             specification threw, so the historical spellings are preserved
     */
    public String serviceValidationFailure(CasFailureCode code, String description) {
        String desc = description == null ? "" : description;
        return "<cas:serviceResponse>"
                + "<cas:authenticationFailure code='" + code.name() + "'>"
                + escape(desc)
                + "</cas:authenticationFailure>"
                + "</cas:serviceResponse>";
    }

    /** CAS 1.0 {@code /cas/validate}: {@code text/plain} "yes\nuser\n" / "no\n\n". */
    public String validateSuccess(String username) {
        return "yes\n" + username + "\n";
    }

    public String validateFailure() {
        return "no\n\n";
    }

    /**
     * SAML 1.1 assertion wrapper - phase 1 only guarantees a well-formed assertion, not semantic
     * equivalence, and the legacy issuer is hard-coded to {@code localhost} (T-12).
     */
    public String samlSuccess(String username, String issuer) {
        String now = java.time.format.DateTimeFormatter.ISO_INSTANT
                .format(java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS));
        return "<SOAP-ENV:Envelope xmlns:SOAP-ENV='http://schemas.xmlsoap.org/soap/envelope/'>"
                + "<SOAP-ENV:Header/>"
                + "<SOAP-ENV:Body>"
                + "<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:1.0:protocol' MajorVersion='1' MinorVersion='1'>"
                + "<samlp:Status>"
                + "<samlp:StatusCode Value='samlp:Success'/>"
                + "</samlp:Status>"
                + "<saml:Assertion xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' MajorVersion='1' MinorVersion='1' AssertionID='_sso_saml_assertion'>"
                + "<saml:Issuer>" + escape(issuer) + "</saml:Issuer>"
                + "<saml:AuthenticationStatement AuthenticationInstant='" + now + "' AuthenticationMethod='urn:oasis:names:tc:SAML:1.0:am:password'>"
                + "<saml:Subject><saml:NameIdentifier NameQualifier='" + escape(issuer) + "'>"
                + escape(username)
                + "</saml:NameIdentifier></saml:Subject>"
                + "</saml:AuthenticationStatement>"
                + "</saml:Assertion>"
                + "</samlp:Response>"
                + "</SOAP-ENV:Body>"
                + "</SOAP-ENV:Envelope>";
    }

    public String samlFailure(String code, String description) {
        return "<SOAP-ENV:Envelope xmlns:SOAP-ENV='http://schemas.xmlsoap.org/soap/envelope/'>"
                + "<SOAP-ENV:Header/>"
                + "<SOAP-ENV:Body>"
                + "<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:1.0:protocol' MajorVersion='1' MinorVersion='1'>"
                + "<samlp:Status>"
                + "<samlp:StatusCode Value='samlp:Requester'/>"
                + "<samlp:StatusMessage>" + escape(code + ": " + description) + "</samlp:StatusMessage>"
                + "</samlp:Status>"
                + "</samlp:Response>"
                + "</SOAP-ENV:Body>"
                + "</SOAP-ENV:Envelope>";
    }

    /**
     * XML text escaping. The legacy JSP relied on JSTL's {@code c:out} default escaping; we escape
     * {@code & < >} plus the quote characters so attribute-free element content round-trips exactly.
     */
    String escape(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&#39;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Content type of the legacy failure view. */
    public static final String FAILURE_CONTENT_TYPE = "text/plain;charset=" + StandardCharsets.UTF_8.name();
}
