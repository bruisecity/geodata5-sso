package cn.geodata.sso.cas.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * T-14 hedge, POST side: both mount prefixes must authenticate.
 *
 * <p>Spring Security's form-login filter matches exactly <em>one</em> processing URL. Section 5.2C
 * records that {@code cas.properties} claims {@code ${server.name}/cas} while every legacy client is
 * configured with the bare root, so whichever single URL we pick, the other prefix breaks. A POST to
 * the non-canonical prefix would fall through to the controller and be treated as a page render
 * instead of a credential submission - a silent login failure, which is exactly the kind of defect
 * that only shows up in production.
 *
 * <p>This filter rewrites the inbound path (login POST only, nothing else) onto the canonical
 * processing URL so both prefixes reach the same filter, and records which prefix the browser
 * actually used so the success/failure handlers can redirect back to that prefix instead of always
 * to {@code /login}.
 */
public class CasLoginPrefixRewriteFilter extends OncePerRequestFilter {

    /** Request attribute carrying the prefix the client used: {@code ""} or {@code "/cas"}. */
    public static final String MOUNT_PREFIX_ATTR = "cn.geodata.sso.cas.MOUNT_PREFIX";

    private static final String LOGIN_SUFFIX = "/login";

    private final String canonicalPath;

    private final List<String> acceptedPaths;

    public CasLoginPrefixRewriteFilter(String canonicalPath, List<String> acceptedPaths) {
        this.canonicalPath = canonicalPath;
        this.acceptedPaths = List.copyOf(acceptedPaths);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        String path = pathWithinApplication(request);
        if (!acceptedPaths.contains(path)) {
            chain.doFilter(request, response);
            return;
        }

        // Record the prefix before rewriting, so downstream handlers still know where to send the
        // browser back to. "/cas/login" -> "/cas"; "/login" -> "".
        String prefix = path.substring(0, path.length() - LOGIN_SUFFIX.length());
        request.setAttribute(MOUNT_PREFIX_ATTR, prefix);

        if (path.equals(canonicalPath)) {
            chain.doFilter(request, response);
            return;
        }
        chain.doFilter(new PrefixRewrittenRequest(request, canonicalPath), response);
    }

    /**
     * Resolves the prefix the request arrived on, for building redirects.
     *
     * @return {@code ""} for the bare root, {@code "/cas"} for the prefixed mount.
     */
    public static String prefixOf(HttpServletRequest request) {
        Object recorded = request.getAttribute(MOUNT_PREFIX_ATTR);
        if (recorded instanceof String s) {
            return s;
        }
        String path = pathWithinApplication(request);
        String base = path.endsWith(LOGIN_SUFFIX)
                ? path.substring(0, path.length() - LOGIN_SUFFIX.length())
                : "";
        return base;
    }

    private static String pathWithinApplication(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String ctx = request.getContextPath();
        return ctx != null && !ctx.isEmpty() && uri.startsWith(ctx) ? uri.substring(ctx.length()) : uri;
    }

    /**
     * Presents the request as if it had been posted to the canonical path, leaving everything else
     * (parameters, headers, session, security context) untouched.
     *
     * <p>Besides the URI/servletPath, this also refreshes Spring's cached
     * {@code ServletRequestPathUtils.PATH_ATTRIBUTE}: Spring Security 7's
     * {@code PathPatternRequestMatcher} reads the path from that request attribute when present
     * (it is cached before the security filter chain runs), so a wrapper that only overrides
     * {@code getRequestURI()} is silently ignored by every path matcher - a defect found by the
     * runtime smoke test: POST /login fell through to the controller (405) while POST /cas/login
     * authenticated.
     */
    static final class PrefixRewrittenRequest extends HttpServletRequestWrapper {

        private final String canonicalUri;

        private final String canonicalServletPath;

        PrefixRewrittenRequest(HttpServletRequest request, String canonicalPath) {
            super(request);
            String ctx = request.getContextPath() == null ? "" : request.getContextPath();
            this.canonicalUri = ctx + canonicalPath;
            this.canonicalServletPath = canonicalPath;
        }

        @Override
        public String getRequestURI() {
            return canonicalUri;
        }

        @Override
        public String getServletPath() {
            return canonicalServletPath;
        }

        @Override
        public StringBuffer getRequestURL() {
            return new StringBuffer(determineScheme()).append("://").append(getServerName())
                    .append(getServerPort() > 0 ? ":" + getServerPort() : "").append(canonicalUri);
        }

        private String determineScheme() {
            String forwarded = getHeader("X-Forwarded-Proto");
            return forwarded == null || forwarded.isBlank() ? getScheme() : forwarded;
        }

        /**
         * Rewrites the cached parsed path as well, so PathPatternRequestMatcher sees the
         * canonical path. The original attribute (cached from the pre-rewrite URI) would otherwise
         * win over every overridden accessor.
         */
        @Override
        public Object getAttribute(String name) {
            if (org.springframework.web.util.ServletRequestPathUtils.PATH_ATTRIBUTE.equals(name)) {
                Object raw = super.getAttribute(name);
                if (raw instanceof org.springframework.http.server.RequestPath rp
                        && !canonicalServletPath.equals(rp.pathWithinApplication().value())) {
                    return org.springframework.http.server.RequestPath.parse(
                            canonicalUri, rp.contextPath().value());
                }
                return raw;
            }
            return super.getAttribute(name);
        }
    }
}
