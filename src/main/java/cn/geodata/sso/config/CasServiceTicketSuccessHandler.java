package cn.geodata.sso.config;

import cn.geodata.sso.cas.ticket.CasTicket;
import cn.geodata.sso.cas.ticket.CasTicketRegistry;
import cn.geodata.sso.cas.web.CasEndpointController;
import cn.geodata.sso.user.CasUserPrincipal;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

/**
 * On a successful login, behave like the legacy webflow: if a {@code service} was supplied, mint an
 * ST, set the {@code CASTGC} cookie and 302 back to {@code service?ticket=ST-...}. Without a
 * {@code service}, simply return to the login endpoint in its authenticated form.
 *
 * <p>This handler exists because the legacy redirect targets are dynamic (the service URL comes
 * from the request), which the declarative {@code defaultSuccessUrl} cannot express.
 */
@Component
public class CasServiceTicketSuccessHandler implements AuthenticationSuccessHandler {

    private final CasTicketRegistry tickets;
    private final SsoProperties props;

    public CasServiceTicketSuccessHandler(CasTicketRegistry tickets, SsoProperties props) {
        this.tickets = tickets;
        this.props = props;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        String service = request.getParameter("service");
        if (!(authentication.getPrincipal() instanceof CasUserPrincipal principal)) {
            response.sendRedirect("/login");
            return;
        }

        if (service == null || service.isBlank()) {
            response.sendRedirect("/login");
            return;
        }

        // Reuse the live TGT when the cookie is present, otherwise mint one and set the cookie.
        String existing = readCookie(request);
        CasTicket tgt = existing == null ? null : tickets.touchTicketGrantingTicket(existing).orElse(null);
        if (tgt == null) {
            tgt = tickets.createTicketGrantingTicket(principal.getUsername(), principal.getAttributes());
            setCookie(response, request, tgt.getId());
        }

        CasTicket st = tickets.createServiceTicket(service, tgt, true);
        response.sendRedirect(appendTicket(service, st.getId()));
    }

    private String readCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }
        for (var c : request.getCookies()) {
            if (props.getCas().getTicketCookieName().equals(c.getName())) {
                return c.getValue();
            }
        }
        return null;
    }

    private void setCookie(HttpServletResponse response, HttpServletRequest request, String tgtId) {
        jakarta.servlet.http.Cookie cookie = new jakarta.servlet.http.Cookie(
                props.getCas().getTicketCookieName(), tgtId);
        cookie.setPath(props.getCas().getTicketCookiePath() == null || props.getCas().getTicketCookiePath().isBlank()
                ? "/" : props.getCas().getTicketCookiePath());
        cookie.setHttpOnly(true);
        cookie.setSecure(request.isSecure());
        cookie.setMaxAge((int) props.getCas().getTicketGrantingTicketMaxLifetime().toSeconds());
        response.addCookie(cookie);
    }

    /** Same rule as {@link CasEndpointController#appendQuery}: keep existing parameters intact. */
    static String appendTicket(String service, String st) {
        int hash = service.indexOf('#');
        String base = hash >= 0 ? service.substring(0, hash) : service;
        String fragment = hash >= 0 ? service.substring(hash) : "";
        String sep = base.contains("?") ? (base.endsWith("?") || base.endsWith("&") ? "" : "&") : "?";
        return base + sep + "ticket=" + st + fragment;
    }
}
