package cn.geodata.sso.api;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Demonstrates the two machine-facing contract points required by phase 1:
 * <ul>
 *   <li>{@code /api/me} - a user-context API reached with a JWT, proving the resource-server path
 *       and proving that 401 (no token) is distinguishable from 403 (insufficient scope).</li>
 *   <li>{@code /api/ping} - any valid token, including a client-credentials service token.</li>
 * </ul>
 */
@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sub", jwt.getSubject());
        body.put("client_id", jwt.getClaim("client_id"));
        body.put("preferred_username", jwt.getClaim("preferred_username"));
        body.put("name", jwt.getClaim("name"));
        body.put("email", jwt.getClaim("email"));
        body.put("org", jwt.getClaim("org"));
        body.put("source", jwt.getClaim("source"));
        body.put("scope", jwt.getClaim("scope"));
        body.put("actor_type", jwt.getClaim("actor_type"));
        return ResponseEntity.ok(body);
    }

    @GetMapping("/ping")
    public ResponseEntity<Map<String, Object>> ping(@AuthenticationPrincipal Jwt jwt, Principal principal) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("pong", true);
        body.put("sub", jwt.getSubject());
        body.put("client_id", jwt.getClaim("client_id"));
        body.put("scope", jwt.getClaim("scope"));
        return ResponseEntity.ok(body);
    }
}
