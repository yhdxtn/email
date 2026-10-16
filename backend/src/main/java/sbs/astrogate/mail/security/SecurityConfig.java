package sbs.astrogate.mail.security;

import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import sbs.astrogate.mail.core.Config;
import sbs.astrogate.mail.service.Store;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    @Bean PasswordEncoder passwords(){return new BCryptPasswordEncoder(12);}
    @Bean SecurityFilterChain security(HttpSecurity http,Store s,ClientIpResolver clientIps)throws Exception{
        var repo=CookieCsrfTokenRepository.withHttpOnlyFalse();
        repo.setCookieName(Config.local()?"XSRF-TOKEN":"__Host-XSRF-TOKEN");
        repo.setCookieCustomizer(c->c.secure(!Config.local()).sameSite("Strict").path("/"));
        http.sessionManagement(c->c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(c->c.csrfTokenRepository(repo).csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
            .formLogin(c->c.disable()).httpBasic(c->c.disable()).logout(c->c.disable())
            .authorizeHttpRequests(c->c
                .requestMatchers("/api/v1/setup/status","/api/v1/setup/initialize","/api/v1/auth/login","/api/v1/auth/csrf","/livez").permitAll()
                .requestMatchers("/api/v1/auth/**").authenticated()
                .requestMatchers("/api/v1/**").hasAnyRole("Owner","MailAdmin","DnsAdmin","Operator","Auditor","WebsiteUserAdmin")
                .anyRequest().denyAll())
            .headers(c->c.contentSecurityPolicy(p->p.policyDirectives("default-src 'none'; frame-ancestors 'none'"))
                .httpStrictTransportSecurity(h->h.includeSubDomains(false).maxAgeInSeconds(31536000)))
            .exceptionHandling(c->c.authenticationEntryPoint((req,res,e)->{
                res.setStatus(401);res.setContentType("application/json");s.json.writeValue(res.getOutputStream(),Map.of("code","AUTH_REQUIRED","message","请先登录","requestId",String.valueOf(req.getAttribute("requestId"))));
            }).accessDeniedHandler((req,res,e)->{
                res.setStatus(403);res.setContentType("application/json");s.json.writeValue(res.getOutputStream(),Map.of("code","FORBIDDEN","message","权限不足或 CSRF 验证失败","requestId",String.valueOf(req.getAttribute("requestId"))));
            }))
            .addFilterBefore(new SessionFilter(s,clientIps),UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
