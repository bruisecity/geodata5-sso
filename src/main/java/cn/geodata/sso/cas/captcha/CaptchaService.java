package cn.geodata.sso.cas.captcha;

import cn.geodata.sso.config.SsoProperties;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.imageio.ImageIO;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Component;

/**
 * Replacement for the legacy {@code com.nauth.ImageCaptchaServlet} served at
 * {@code /cas/captcha.jpg} (architecture 5.2).
 *
 * <p>The legacy login flow forced a captcha before {@code realSubmit}
 * ({@code login-webflow.xml}). We keep the capability and the endpoint name; the challenge is
 * stored in the HTTP session under the legacy-compatible key so a session-aware login filter can
 * verify it.
 *
 * <p>Rendered with {@link BufferedImage} so no native dependency is needed.
 */
@Component
public class CaptchaService {

    /** Legacy servlet stored the expected text under this session key. */
    public static final String SESSION_KEY = "cas_captcha";

    private final SsoProperties props;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, String> fallbackStore = new ConcurrentHashMap<>();

    private static final String ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

    public CaptchaService(SsoProperties props) {
        this.props = props;
    }

    public String generateText() {
        int len = props.getCas().getCaptcha().getLength();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(ALPHABET.charAt(random.nextInt(ALPHABET.length())));
        }
        return sb.toString();
    }

    public byte[] render(String text) throws IOException {
        int w = props.getCas().getCaptcha().getWidth();
        int h = props.getCas().getCaptcha().getHeight();
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(new Color(0xF4F6F9));
        g.fillRect(0, 0, w, h);

        // noise
        for (int i = 0; i < 24; i++) {
            g.setColor(new Color(random.nextInt(200), random.nextInt(200), random.nextInt(200)));
            g.drawLine(random.nextInt(w), random.nextInt(h), random.nextInt(w), random.nextInt(h));
        }

        g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 22));
        for (int i = 0; i < text.length(); i++) {
            g.setColor(new Color(random.nextInt(120), random.nextInt(120), random.nextInt(160)));
            int y = 23 + random.nextInt(4) - 2;
            g.drawString(String.valueOf(text.charAt(i)), 8 + i * 20, y);
        }
        g.dispose();
        try (var out = new java.io.ByteArrayOutputStream()) {
            ImageIO.write(img, "png", out);
            return out.toByteArray();
        }
    }

    /** Stores the expected challenge; session may be null in stateless smoke tests. */
    public void store(HttpSession session, String text) {
        if (session != null) {
            session.setAttribute(SESSION_KEY, text);
        } else {
            fallbackStore.put("nobody", text);
        }
    }

    public boolean verify(HttpSession session, String supplied) {
        if (supplied == null || supplied.isBlank()) {
            return false;
        }
        String expected = session == null ? fallbackStore.remove("nobody") : (String) session.getAttribute(SESSION_KEY);
        if (session != null) {
            session.removeAttribute(SESSION_KEY);
        }
        return expected != null && expected.equalsIgnoreCase(supplied.trim());
    }
}
