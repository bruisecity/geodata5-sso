package cn.geodata.sso.cas.web;

import cn.geodata.sso.cas.captcha.CaptchaService;
import cn.geodata.sso.config.SsoProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Legacy {@code /cas/captcha.jpg} endpoint ({@code com.nauth.ImageCaptchaServlet}).
 *
 * <p>Mounted under both prefixes for the same T-14 reason as the other CAS endpoints.
 */
@Controller
public class CasCaptchaController {

    private final CaptchaService captcha;

    public CasCaptchaController(CaptchaService captcha, SsoProperties ignored) {
        this.captcha = captcha;
    }

    @GetMapping({"/captcha.jpg", "/cas/captcha.jpg"})
    public void captcha(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String text = captcha.generateText();
        captcha.store(request.getSession(true), text);
        byte[] png = captcha.render(text);
        response.setContentType(MediaType.IMAGE_PNG_VALUE);
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.getOutputStream().write(png);
        response.getOutputStream().flush();
    }
}
