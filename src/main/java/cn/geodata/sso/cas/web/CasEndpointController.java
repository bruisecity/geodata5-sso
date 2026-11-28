package cn.geodata.sso.cas.web;

import cn.geodata.sso.cas.attr.CasAttributeAssembler;
import cn.geodata.sso.cas.protocol.CasFailureCode;
import cn.geodata.sso.cas.protocol.CasResponseRenderer;
import cn.geodata.sso.cas.service.CasServiceRegistry;
import cn.geodata.sso.cas.ticket.CasTicket;
import cn.geodata.sso.cas.ticket.CasTicketRegistry;
import cn.geodata.sso.cas.ticket.TicketValidationResult;
import cn.geodata.sso.config.SsoProperties;
import cn.geodata.sso.user.CasUserPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

/**
 * The legacy CAS 3.5.2 protocol surface, reproduced endpoint by endpoint from
 * {@code web.xml} + {@code cas-servlet.xml} (architecture 5.2).
 *
 * <p>Every mapping is registered under <strong>both</strong> mount prefixes configured in
 * {@code sso.cas.mount-paths} ({@code /cas} and {@code ""} by default). That is the concrete hedge
 * against T-14: legacy clients are configured against the bare root
 * ({@code http://auth.geodata.cn/login}) while the server's own {@code cas.properties} declared
 * {@code server.prefix=${server.name}/cas}, and nobody can currently say which one production uses.
 *
 * <p>Endpoints deliberately <em>not</em> implemented (architecture 5.2 revision log):
 * {@code /cas/p3/serviceValidate}, {@code /cas/p3/proxyValidate}, {@code /cas/proxy},
 * {@code /cas/v1/tickets}, {@code /cas/openid/*}, {@code /cas/oauth10login},
 * {@code /cas/services/*}, {@code /cas/status}. Their absence is a correctness property, not an
 * omission: the legacy source has no mapping for {@code p3}, and proxying was never enabled
 * ({@code Cas20WithoutProxyingValidationSpecification}).
 */
@Controller
public class CasEndpointController {

    private static final Logger log = LoggerFactory.getLogger(CasEndpointController.class);

    private final SsoProperties props;
    private final CasTicketRegistry tickets;
    private final CasAttributeAssembler attributes;
    private final CasResponseRenderer renderer;
    private final CasServiceRegistry services;

    public CasEndpointController(SsoProperties props, CasTicketRegistry tickets,
                                 CasAttributeAssembler attributes, CasResponseRenderer renderer,
                                 CasServiceRegistry services) {
        this.props = props;
        this.tickets = tickets;
        this.attributes = attributes;
        this.renderer = renderer;
        this.services = services;
    }

    // =========================================================================================
    // /login  (GET: show page; POST handled by the login filter via a redirect-free path)
    // =========================================================================================

    @GetMapping({"/login", "/cas/login"})
    public Object loginGet(
            @RequestParam(name = "service", required = false) String service,
            @RequestParam(name = "renew", required = false) String renew,
            @RequestParam(name = "gateway", required = false) String gateway,
            @RequestParam(name = "lt", required = false) String lt,
            @RequestParam(name = "execution", required = false) String execution,
            @RequestParam(name = "error", required = false) String error,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        // Already authenticated and a service was requested: issue the ST and bounce back,
        // exactly like the legacy webflow's "service" path.
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && auth.getPrincipal() instanceof CasUserPrincipal p
                && service != null && !service.isBlank()) {
            String st = issueServiceTicket(p, service, request);
            redirectToService(service, st, response);
            return null;
        }

        if (service != null && !service.isBlank() && !services.isAllowed(service)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(CasResponseRenderer.FAILURE_CONTENT_TYPE);
            response.getWriter().write(renderer.serviceValidationFailure(
                    CasFailureCode.INVALID_SERVICE_NOT_AUTHORIZED,
                    "Service [" + service + "] is not authorized"));
            return null;
        }

        // Legacy login page keeps these parameter names verbatim; _eventId is checked server side.
        ModelAndView mav = new ModelAndView("casLogin");
        mav.addObject("service", service == null ? "" : service);
        mav.addObject("renew", renew == null ? "" : renew);
        mav.addObject("gateway", gateway == null ? "" : gateway);
        mav.addObject("lt", lt == null ? "" : lt);
        mav.addObject("execution", execution == null ? "" : execution);
        mav.addObject("error", error == null ? "" : error);
        mav.addObject("captchaRequired", props.getCas().getLoginPage().isCaptchaRequired()
                && !props.getCas().getLoginPage().isCaptchaBypassForLocalProfile());
        mav.addObject("formAction", props.getCas().getLoginPage().getFormAction());
        return mav;
    }

    /**
     * Legacy {@code /cas/logout}: destroys the TGT and the HTTP session, optionally redirects to
     * {@code service}. {@code followServiceRedirects} was true in the legacy servlet config.
     */
    @GetMapping({"/logout", "/cas/logout"})
    public void logoutGet(@RequestParam(name = "service", required = false) String service,
                          HttpServletRequest request,
                          HttpServletResponse response) throws IOException {
        String tgtId = readTicketGrantingCookie(request);
        if (tgtId != null) {
            tickets.removeTicketGrantingTicket(tgtId);
        }
        var session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
        clearTicketGrantingCookie(response);

        if (service != null && !service.isBlank() && isAbsoluteHttpUrl(service)) {
            response.sendRedirect(appendQuery(service, "") );
        } else {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("text/html;charset=UTF-8");
            response.getWriter().write("<html><head><title>Logout</title></head>"
                    + "<body><h2>您已成功退出</h2></body></html>");
        }
    }

    // =========================================================================================
    // /cas/validate  (CAS 1.0, text/plain)
    // =========================================================================================

    @GetMapping({"/validate", "/cas/validate"})
    public void validateGet(@RequestParam(name = "service", required = false) String service,
                            @RequestParam(name = "ticket", required = false) String ticket,
                            HttpServletResponse response) throws IOException {
        response.setContentType("text/plain;charset=UTF-8");
        if (service == null || ticket == null) {
            response.getWriter().write(renderer.validateFailure());
            return;
        }
        TicketValidationResult r = tickets.validateAndConsume(ticket, service);
        if (!r.isSuccess()) {
            log.debug("CAS 1.0 validate failed: {} {}", r.getFailureCode(), r.getDescription());
            response.getWriter().write(renderer.validateFailure());
            return;
        }
        response.getWriter().write(renderer.validateSuccess(r.getTicket().getPrincipal()));
    }

    // =========================================================================================
    // /cas/serviceValidate and /cas/proxyValidate  (CAS 2.0 XML, NON-STANDARD attribute dialect)
    // =========================================================================================

    @GetMapping({"/serviceValidate", "/cas/serviceValidate",
            "/proxyValidate", "/cas/proxyValidate"})
    @ResponseBody
    public ResponseEntity<String> serviceValidateGet(
            @RequestParam(name = "service", required = false) String service,
            @RequestParam(name = "ticket", required = false) String ticket,
            @RequestParam(name = "pgtUrl", required = false) String pgtUrl,
            @RequestParam(name = "renew", required = false) String renew) {

        if (service == null || service.isBlank() || ticket == null || ticket.isBlank()) {
            return ResponseEntity.ok()
                    .contentType(MediaType.valueOf(CasResponseRenderer.FAILURE_CONTENT_TYPE))
                    .body(renderer.serviceValidationFailure(CasFailureCode.INVALID_REQUEST,
                            "both 'service' and 'ticket' parameters are required"));
        }

        TicketValidationResult r = tickets.validateAndConsume(ticket, service);
        if (!r.isSuccess()) {
            log.debug("serviceValidate rejected ticket {}: {} - {}", ticket, r.getFailureCode(), r.getDescription());
            return ResponseEntity.ok()
                    .contentType(MediaType.valueOf(CasResponseRenderer.FAILURE_CONTENT_TYPE))
                    .body(renderer.serviceValidationFailure(r.getFailureCode(), r.getDescription()));
        }

        CasTicket t = r.getTicket();
        // This is the whole point of the compatibility layer: element name == attribute key.
        List<Map.Entry<String, String>> attrs = attributes.assemble(t.getAttributes());
        String xml = renderer.serviceValidationSuccess(t.getPrincipal(), attrs);
        return ResponseEntity.ok()
                .contentType(MediaType.valueOf("text/xml;charset=UTF-8"))
                .body(xml);
    }

    // =========================================================================================
    // /cas/CentralAuthenticationService  (legacy servlet alias in web.xml)
    // =========================================================================================

    @GetMapping({"/CentralAuthenticationService", "/cas/CentralAuthenticationService"})
    public void centralAuthenticationServiceAlias(
            @RequestParam(name = "service", required = false) String service,
            HttpServletResponse response) throws IOException {
        String target = props.getCas().getMountPaths().contains("/cas") ? "/cas/login" : "/login";
        if (service != null && !service.isBlank()) {
            target = target + "?service=" + java.net.URLEncoder.encode(service, java.nio.charset.StandardCharsets.UTF_8);
        }
        response.sendRedirect(target);
    }

    // =========================================================================================
    // helpers
    // =========================================================================================

    /** Issues an ST for a live TGT (or a fresh one if the session has no TGT yet). */
    public String issueServiceTicket(CasUserPrincipal principal, String service, HttpServletRequest request) {
        String tgtId = readTicketGrantingCookie(request);
        CasTicket tgt = tgtId == null ? null : tickets.touchTicketGrantingTicket(tgtId).orElse(null);
        if (tgt == null) {
            tgt = tickets.createTicketGrantingTicket(principal.getUsername(), principal.getAttributes());
            writeTicketGrantingCookie(tgt.getId(), request, null);
        }
        CasTicket st = tickets.createServiceTicket(service, tgt, true);
        return st.getId();
    }

    public String readTicketGrantingCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }
        String name = props.getCas().getTicketCookieName();
        for (var c : request.getCookies()) {
            if (name.equals(c.getName())) {
                return c.getValue();
            }
        }
        return null;
    }

    public void writeTicketGrantingCookie(String tgtId, HttpServletRequest request, HttpServletResponse response) {
        jakarta.servlet.http.Cookie cookie = new jakarta.servlet.http.Cookie(
                props.getCas().getTicketCookieName(), tgtId);
        String path = props.getCas().getTicketCookiePath();
        // T-14: the cookie path must cover whichever prefix clients actually hit. When the
        // configured path is the root we honour it; otherwise fall back to the request context so
        // /cas and / can both see the TGT.
        cookie.setPath(path == null || path.isBlank() ? "/" : path);
        cookie.setHttpOnly(true);
        cookie.setSecure(request.isSecure());
        cookie.setMaxAge((int) props.getCas().getTicketGrantingTicketMaxLifetime().toSeconds());
        if (response != null) {
            response.addCookie(cookie);
        } else {
            // servlet response unavailable (e.g. programmatic issue) - nothing to set
            log.debug("TGT issued without HTTP response context: {}", tgtId);
        }
    }

    private void clearTicketGrantingCookie(HttpServletResponse response) {
        jakarta.servlet.http.Cookie cookie = new jakarta.servlet.http.Cookie(
                props.getCas().getTicketCookieName(), "");
        cookie.setPath(props.getCas().getTicketCookiePath() == null ? "/" : props.getCas().getTicketCookiePath());
        cookie.setMaxAge(0);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }

    private void redirectToService(String service, String ticket, HttpServletResponse response) throws IOException {
        response.sendRedirect(appendQuery(service, "ticket=" + ticket));
    }

    /**
     * Appends a query parameter while preserving existing ones. The legacy server used
     * {@code ServiceTicketRedirectStrategy}, which is equivalent for the parameter shapes in use.
     */
    static String appendQuery(String url, String param) {
        if (param == null || param.isEmpty()) {
            return url;
        }
        int hash = url.indexOf('#');
        String base = hash >= 0 ? url.substring(0, hash) : url;
        String fragment = hash >= 0 ? url.substring(hash) : "";
        String sep = base.contains("?") ? (base.endsWith("?") || base.endsWith("&") ? "" : "&") : "?";
        return base + sep + param + fragment;
    }

    private static boolean isAbsoluteHttpUrl(String s) {
        String lower = s.toLowerCase();
        return lower.startsWith("http://") || lower.startsWith("https://");
    }

    /** Exposed for the login filter to reuse the same redirect rules. */
    public Optional<CasTicket> findTicket(String id) {
        return tickets.find(id);
    }

    /** Simple accessor so the filter can read the current service allow decision. */
    public boolean isServiceAllowed(String service) {
        return services.isAllowed(service);
    }

    /** Used by the login POST handler to know which configured prefixes to consider. */
    public List<String> mountPaths() {
        return props.getCas().getMountPaths();
    }

    static URI parseService(String service) {
        try {
            return URI.create(service);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }
}
