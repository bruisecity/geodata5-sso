package cn.geodata.sso.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

/**
 * Spring Authorization Server wiring.
 *
 * <p>Auto-configuration backs off when the application declares a {@code SecurityFilterChain}, so
 * every collaborator (repository, authorization service, settings, JWK source, token customizer) is
 * registered explicitly. Doing it here rather than relying on defaults also makes the
 * "public client must use PKCE" rule (architecture 10.1) a visible, reviewable line of code.
 *
 * <p>Token lifetimes follow architecture 4.1: user access token 15 minutes, service access token
 * 10 minutes, refresh 30 days - expressed as token settings on each client so a stricter client can
 * be dialled in later without touching code.
 */
@Configuration
public class AuthorizationServerConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbc) {
        // SAS 7.1.3 ships both Jackson2 and Jackson3 row mappers and selects one at runtime, so this
        // works under Boot 4.x's Jackson 3 without extra configuration.
        return new JdbcRegisteredClientRepository(jdbc);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbc,
                                                           RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationService(jdbc, clients);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcTemplate jdbc, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(jdbc, clients);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(SsoProperties props) {
        return AuthorizationServerSettings.builder()
                .issuer(props.getIssuer())
                .build();
    }

    /**
     * RS256 signing key. Generated at startup for the skeleton: production must supply a stable,
     * externally stored key, otherwise every restart invalidates all outstanding tokens and breaks
     * the "issuer/JWKS is a contract" property from architecture 4.2.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to generate RSA key pair", ex);
        }
    }

    /** Exposes the configurer as a bean so the security chain can consume its endpoint matcher. */
    @Bean
    public OAuth2AuthorizationServerConfigurer authorizationServerConfigurer() {
        return new OAuth2AuthorizationServerConfigurer();
    }

    /**
     * Builds a registered client from a seed definition.
     *
     * <p>PKCE: public clients get {@code requireProofKey(true)} and no secret; confidential clients
     * keep {@code client_secret_basic} primary with {@code client_secret_post} accepted because the
     * legacy ecosystem posts form-encoded credentials.
     */
    public static RegisteredClient buildClient(SsoProperties.Bootstrap.SeedClient seed) {
        // Grant selection is driven by what the client actually is, not by "confidential vs public":
        // a service identity (no redirect URI, no interactive user) is client_credentials only.
        // Registering authorization_code for it trips RegisteredClient.Builder's invariant
        // ("redirectUris cannot be empty"), which is the correct framework behaviour, not a bug.
        boolean serviceIdentity = !seed.isPublicClient()
                && (seed.getRedirectUris() == null || seed.getRedirectUris().isEmpty());

        RegisteredClient.Builder b = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(seed.getClientId())
                .clientName(seed.getClientName() == null ? seed.getClientId() : seed.getClientName());

        if (seed.isPublicClient()) {
            b.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        } else {
            b.clientSecret("{noop}" + seed.getClientSecret())
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
        }

        if (seed.getRedirectUris() != null && !seed.getRedirectUris().isEmpty()) {
            seed.getRedirectUris().forEach(b::redirectUri);
        }
        if (seed.getScopes() != null) {
            seed.getScopes().forEach(b::scope);
        }

        if (serviceIdentity) {
            // 场景二 (architecture 3.2): server-to-server calls carry no user and no redirect.
            b.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
        } else if (seed.isPublicClient()) {
            // PKCE-only interactive client: no client_credentials (it has no secret at all).
            b.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        } else {
            // interactive confidential client: full phase-1 grant set
            b.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
        }

        b.clientSettings(ClientSettings.builder()
                .requireProofKey(seed.isPublicClient())
                .requireAuthorizationConsent(false) // first-party apps in phase 1
                .build());

        b.tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(seed.isPublicClient()
                        ? java.time.Duration.ofMinutes(15) : java.time.Duration.ofMinutes(10))
                .refreshTokenTimeToLive(java.time.Duration.ofDays(30))
                .reuseRefreshTokens(false) // rotation, architecture 4.3
                .build());

        return b.build();
    }
}
