package cn.geodata.sso.config;

import cn.geodata.sso.user.LegacyDualPasswordAuthenticationProvider;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * One place where all filter chains are ordered and their responsibilities declared.
 *
 * <p>Important Boot 4.x behaviour: {@code OAuth2AuthorizationServerAutoConfiguration} backs off as
 * soon as we declare our own {@code SecurityFilterChain}, so the authorization server is wired
 * explicitly here and in {@link AuthorizationServerConfig}. The three chains, in order:
 *
 * <ol>
 *   <li><strong>Authorization server endpoints</strong> - SAS matcher, Bearer-authenticated exits.</li>
 *   <li><strong>CAS compatibility endpoints</strong> - {@code /login}, {@code /cas/**} and the bare
 *       root variants; form login lives here because the legacy login page posts to {@code /login}.</li>
 *   <li><strong>Application / API</strong> - JWT-protected {@code /api/**}, everything else public
 *       only where it must be (login page, captcha, discovery, jwks).</li>
 * </ol>
 */
@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        // New hashes are BCrypt; legacy values are compared as plain text by the provider, never here.
        return new BCryptPasswordEncoder();
    }

    /**
     * Canonical form-login POST target: the prefixed mount when configured, bare root otherwise.
     */
    static String loginProcessingUrl(SsoProperties props) {
        return props.getCas().getMountPaths().stream()
                .filter(p -> p != null && !p.isBlank())
                .findFirst()
                .map(p -> p + "/login")
                .orElse("/login");
    }

    /** Every login POST path that must authenticate, one per configured mount prefix. */
    static java.util.List<String> loginAcceptedPaths(SsoProperties props) {
        return props.getCas().getMountPaths().stream()
                .map(p -> p == null ? "" : p)
                .distinct()
                .map(p -> p + "/login")
                .toList();
    }

    /**
     * Bare-root and prefixed CAS paths all funnel through one matcher so the login page and the
     * protocol endpoints keep identical semantics under both mount prefixes (T-14 hedge).
     */
    static RequestMatcher casPaths() {
        return new OrRequestMatcher(
                PathPatternRequestMatcher.pathPattern("/cas/**"),
                PathPatternRequestMatcher.pathPattern("/login"),
                PathPatternRequestMatcher.pathPattern("/logout"),
                PathPatternRequestMatcher.pathPattern("/captcha.jpg"),
                PathPatternRequestMatcher.pathPattern("/CentralAuthenticationService"),
                PathPatternRequestMatcher.pathPattern("/validate"),
                PathPatternRequestMatcher.pathPattern("/serviceValidate"),
                PathPatternRequestMatcher.pathPattern("/proxyValidate"));
    }

    /**
     * Chain 1: the authorization server's own endpoints.
     *
     * <p>Declared as a plain chain (rather than via the convenience
     * {@code authorizationServerSecurityFilterChain} helper) so the ordering relative to the CAS chain
     * is explicit and cannot silently flip when a new dependency changes defaults.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerChain(
            HttpSecurity http,
            org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization
                    .OAuth2AuthorizationServerConfigurer authorizationServerConfigurer) throws Exception {
        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, org.springframework.security.config.Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .exceptionHandling(ex -> ex
                        .defaultAuthenticationEntryPointFor(
                                new BearerTokenAuthenticationEntryPoint(),
                                PathPatternRequestMatcher.pathPattern("/oauth2/**"))
                        .defaultAuthenticationEntryPointFor(
                                new BearerTokenAuthenticationEntryPoint(),
                                PathPatternRequestMatcher.pathPattern("/.well-known/**"))
                        .defaultAuthenticationEntryPointFor(
                                new BearerTokenAuthenticationEntryPoint(),
                                PathPatternRequestMatcher.pathPattern("/userinfo"))
                        .accessDeniedHandler(new BearerTokenAccessDeniedHandler()))
                // OIDC requires a session for the authorization-code step (the consent/approval step).
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .csrf(csrf -> csrf.ignoringRequestMatchers(
                        PathPatternRequestMatcher.pathPattern("/oauth2/token"),
                        PathPatternRequestMatcher.pathPattern("/oauth2/revoke"),
                        PathPatternRequestMatcher.pathPattern("/oauth2/introspect")));
        return http.build();
    }

    /**
     * Chain 2: legacy CAS surface, including the form login the legacy login page posts to.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain casChain(HttpSecurity http,
                                        LegacyDualPasswordAuthenticationProvider provider,
                                        CasServiceTicketSuccessHandler casServiceTicketSuccessHandler,
                                        SsoProperties props) throws Exception {
        http.securityMatcher(casPaths())
                .csrf(AbstractHttpConfigurer::disable) // legacy JSP posted no CSRF token
                // Both mount prefixes must authenticate (T-14). Spring Security's form-login filter
                // matches exactly one processing URL, so the inbound POST path is rewritten onto the
                // canonical one and the original prefix is recorded for the redirect handlers.
                .addFilterBefore(
                        new cn.geodata.sso.cas.web.CasLoginPrefixRewriteFilter(
                                loginProcessingUrl(props),
                                loginAcceptedPaths(props)),
                        org.springframework.security.web.authentication
                                .UsernamePasswordAuthenticationFilter.class)
                .authenticationProvider(provider)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                PathPatternRequestMatcher.pathPattern(org.springframework.http.HttpMethod.GET, "/login"),
                                PathPatternRequestMatcher.pathPattern(org.springframework.http.HttpMethod.GET, "/cas/login"),
                                PathPatternRequestMatcher.pathPattern("/captcha.jpg"),
                                PathPatternRequestMatcher.pathPattern("/cas/captcha.jpg"),
                                PathPatternRequestMatcher.pathPattern("/validate"),
                                PathPatternRequestMatcher.pathPattern("/cas/validate"),
                                PathPatternRequestMatcher.pathPattern("/serviceValidate"),
                                PathPatternRequestMatcher.pathPattern("/cas/serviceValidate"),
                                PathPatternRequestMatcher.pathPattern("/proxyValidate"),
                                PathPatternRequestMatcher.pathPattern("/cas/proxyValidate")).permitAll()
                        // logout must be reachable anonymously, otherwise "log out" loops into login
                        .requestMatchers(
                                PathPatternRequestMatcher.pathPattern("/logout"),
                                PathPatternRequestMatcher.pathPattern("/cas/logout")).permitAll()
                        .requestMatchers(
                                PathPatternRequestMatcher.pathPattern("/CentralAuthenticationService"),
                                PathPatternRequestMatcher.pathPattern("/cas/CentralAuthenticationService")).permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        // canonical POST target; the prefix filter makes both prefixes reach it
                        .loginProcessingUrl(loginProcessingUrl(props))
                        .usernameParameter("username")
                        .passwordParameter("password")
                        .successHandler(casServiceTicketSuccessHandler)
                        .failureHandler((request, response, exception) -> {
                            String service = request.getParameter("service");
                            // Honour the prefix the browser actually posted to (T-14).
                            String redirect = cn.geodata.sso.cas.web.CasLoginPrefixRewriteFilter
                                    .prefixOf(request) + "/login?error="
                                    + java.net.URLEncoder.encode("用户名或密码错误", java.nio.charset.StandardCharsets.UTF_8);
                            if (service != null && !service.isBlank()) {
                                redirect += "&service="
                                        + java.net.URLEncoder.encode(service, java.nio.charset.StandardCharsets.UTF_8);
                            }
                            response.sendRedirect(redirect);
                        })
                        .permitAll())
                .logout(logout -> logout
                        .logoutRequestMatcher(new OrRequestMatcher(
                                PathPatternRequestMatcher.pathPattern("/logout"),
                                PathPatternRequestMatcher.pathPattern("/cas/logout")))
                        .logoutSuccessUrl("/login?logout=true")
                        .invalidateHttpSession(true)
                        .deleteCookies(props.getCas().getTicketCookieName(), "JSESSIONID"))
                .exceptionHandling(ex -> ex
                        // For the protocol endpoints a login redirect would break legacy clients:
                        // they expect a protocol response, so CAS validation paths get a 401.
                        .defaultAuthenticationEntryPointFor(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                new OrRequestMatcher(
                                        PathPatternRequestMatcher.pathPattern("/serviceValidate"),
                                        PathPatternRequestMatcher.pathPattern("/cas/serviceValidate"),
                                        PathPatternRequestMatcher.pathPattern("/validate"),
                                        PathPatternRequestMatcher.pathPattern("/cas/validate"))));
        return http.build();
    }

    /**
     * Chain 3: everything else. {@code /api/**} requires a JWT and answers 401/403 distinctly
     * (a redirect to a login page would make the two indistinguishable for API callers).
     */
    @Bean
    @Order(3)
    public SecurityFilterChain applicationChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                PathPatternRequestMatcher.pathPattern("/api/**")).authenticated()
                        .anyRequest().permitAll())
                .oauth2ResourceServer(rs -> rs
                        .jwt(jwt -> {
                        })
                        .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                        .accessDeniedHandler(new BearerTokenAccessDeniedHandler()))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                        .accessDeniedHandler(new BearerTokenAccessDeniedHandler()))
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }
}
