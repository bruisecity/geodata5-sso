package cn.geodata.sso.user;

import cn.geodata.sso.config.SsoProperties;
import java.util.List;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Authentication provider implementing the "dual verification + upgrade on login" path required by
 * architecture 5.7.3.
 *
 * <p>Order of checks:
 * <ol>
 *   <li>Missing account / disabled account -> reject (legacy SQL filtered on {@code enabled=1}).</li>
 *   <li>If our own credential row already has an upgraded BCrypt hash -> verify with BCrypt.</li>
 *   <li>Otherwise fall back to the legacy value: the submitted password is what the browser already
 *       MD5'd, so it is compared as plain text. To also support non-browser clients, the raw
 *       password is additionally digested with the legacy recipe and compared.</li>
 *   <li>On legacy success (and when enabled), write the BCrypt hash + upgrade flag.</li>
 * </ol>
 *
 * <p>Note: the legacy {@code role_id}/{@code role_name} attributes were commented out in source, so
 * role-based authorities are internal only and are never emitted to CAS clients (T-17).
 */
@Component
public class LegacyDualPasswordAuthenticationProvider implements AuthenticationProvider {

    /** Internal authority; deliberately not exported as a CAS attribute. */
    public static final String ROLE_USER = "ROLE_USER";

    private final LegacyUserRepository users;
    private final org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;
    private final SsoProperties props;

    public LegacyDualPasswordAuthenticationProvider(
            LegacyUserRepository users,
            org.springframework.security.crypto.password.PasswordEncoder passwordEncoder,
            SsoProperties props) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.props = props;
    }

    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = String.valueOf(authentication.getPrincipal());
        String presented = String.valueOf(authentication.getCredentials());
        if (username.isBlank() || presented.isEmpty()) {
            throw new BadCredentialsException("Empty username or password");
        }

        LegacyUserRepository.LegacyUser user = users.findByUsername(username)
                .orElseThrow(() -> new BadCredentialsException("Bad credentials"));

        if (!user.isEnabled()) {
            throw new BadCredentialsException("Account disabled");
        }
        // Legacy auth SQL filtered on created_from='CAS'; keep the same gate but let config widen it
        // for local seeds. Prod keeps 'CAS' so behaviour matches the legacy statement exactly.
        String filter = props.getLegacy().getCreatedFromFilter();
        if (filter != null && !filter.isBlank() && !"*".equals(filter)
                && !filter.equalsIgnoreCase(user.getCreatedFrom())) {
            throw new BadCredentialsException("Bad credentials");
        }

        var state = users.findCredentialState(username);
        if (state.isPresent() && state.get().upgraded() && state.get().passwordHash() != null) {
            if (!passwordEncoder.matches(presented, state.get().passwordHash())) {
                users.recordFailedLogin(username, "", "BCRYPT_MISMATCH");
                throw new BadCredentialsException("Bad credentials");
            }
        } else {
            boolean matched = users.matchesLegacyPassword(presented, user.getLegacyPassword());
            if (!matched) {
                // Non-browser clients post the raw password: try the exact legacy digest recipe.
                String digested = LegacyUserRepository.legacyDigest(presented, username);
                matched = users.matchesLegacyPassword(digested, user.getLegacyPassword());
            }
            if (!matched) {
                users.recordFailedLogin(username, "", "LEGACY_MISMATCH");
                throw new BadCredentialsException("Bad credentials");
            }
            if (props.getLegacy().isUpgradePasswordOnLogin()) {
                // Same transaction as the check above: either both land or neither does.
                users.upgradePassword(username, presented);
            }
        }

        var principal = new CasUserPrincipal(
                user.getUsername(),
                user.getUserId(),
                users.toPrincipalAttributes(user),
                List.of(new SimpleGrantedAuthority(ROLE_USER)));
        users.recordSuccessfulLogin(username, "");
        return UsernamePasswordAuthenticationToken.authenticated(principal, presented, principal.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
