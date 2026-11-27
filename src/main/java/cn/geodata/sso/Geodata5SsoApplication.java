package cn.geodata.sso;

import cn.geodata.sso.config.SsoProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Entry point of the geodata5-sso unified authentication center.
 *
 * <p>This application is both:
 * <ul>
 *   <li>an OAuth 2.1 / OpenID Connect authorization server (Spring Authorization Server), and</li>
 *   <li>a drop-in replacement for the legacy Jasig CAS 3.5.2 server ("yelu-cas"), serving the
 *       non-standard attribute dialect produced by the legacy {@code casServiceValidationSuccess.jsp}.</li>
 * </ul>
 */
@SpringBootApplication
@EnableConfigurationProperties(SsoProperties.class)
public class Geodata5SsoApplication {

    public static void main(String[] args) {
        SpringApplication.run(Geodata5SsoApplication.class, args);
    }
}
