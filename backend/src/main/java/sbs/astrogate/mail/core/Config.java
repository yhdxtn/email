package sbs.astrogate.mail.core;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Set;
import java.util.Arrays;
import java.util.stream.Collectors;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class Config {
    public static String env(String name, String fallback) { String v = System.getenv(name); return v == null || v.isBlank() ? fallback : v; }
    public static boolean local() { return env("LOCAL_DEV", "false").equals("true"); }
    public static String origin() { return env("APP_ORIGIN", "https://admin.example.test"); }
    public static String secret(String name) {
        String file = env(name + "_FILE", "");
        if (!file.isEmpty()) {
            try { return Files.readString(Path.of(file)).strip(); }
            catch (Exception e) { throw new IllegalStateException(name + " secret file unavailable"); }
        }
        return env(name, "");
    }
    public static Set<String> set(String name) {
        return Arrays.stream(env(name, "").split(",")).map(String::strip).filter(s -> !s.isEmpty()).collect(Collectors.toUnmodifiableSet());
    }
    @Bean public Crypto crypto() {
        URI origin = URI.create(origin());
        if (!"https".equals(origin.getScheme()) && !(local() && Set.of("127.0.0.1", "localhost").contains(origin.getHost())))
            throw new IllegalStateException("APP_ORIGIN requires HTTPS; local development must use loopback");
        String setup = secret("APP_SETUP_TOKEN");
        if (setup.length() < 32) throw new IllegalStateException("APP_SETUP_TOKEN must be independently generated (32+ characters)");
        try { return new Crypto(Base64.getDecoder().decode(secret("APP_MASTER_KEY"))); }
        catch (IllegalArgumentException e) { throw new IllegalStateException("APP_MASTER_KEY must be 32 random bytes, base64 encoded"); }
    }
}
