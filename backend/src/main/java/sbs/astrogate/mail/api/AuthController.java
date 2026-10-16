package sbs.astrogate.mail.api;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import sbs.astrogate.mail.core.Config;
import sbs.astrogate.mail.security.*;
import sbs.astrogate.mail.service.*;

@RestController
@RequestMapping("/api/v1")
public class AuthController {
    private final AuthService auth;private final Store s;private final Audit audit;private final ClientIpResolver clientIps;
    public AuthController(AuthService auth,Store s,Audit audit,ClientIpResolver clientIps){this.auth=auth;this.s=s;this.audit=audit;this.clientIps=clientIps;}
    public record Setup(@NotBlank @Size(max=256) String token,@NotBlank @Size(max=64) String username,@NotBlank @Size(max=256) String password){}
    public record Login(@NotBlank @Size(max=64) String username,@NotBlank @Size(max=256) String password){}
    public record Reauth(@NotBlank @Size(max=256) String password){}
    @GetMapping("/setup/status") public Map<String,Object> status(){return Map.of("needsSetup",auth.needsSetup(),"version","0.1.0","productionAccepted",false);}
    @PostMapping("/setup/initialize") public Map<String,Object> initialize(@Valid @RequestBody Setup body,HttpServletRequest req){auth.setup(body.token(),body.username(),body.password(),clientIps.resolve(req));return Map.of("initialized",true,"next","login");}
    @GetMapping("/auth/csrf") public Map<String,String> csrf(CsrfToken token){return Map.of("token",token.getToken(),"headerName",token.getHeaderName());}
    @PostMapping("/auth/login") public Map<String,Object> login(@Valid @RequestBody Login body,HttpServletRequest req,HttpServletResponse res){
        String token=auth.login(body.username(),body.password(),clientIps.resolve(req),req.getHeader("User-Agent"));cookie(res,token,28800);return Map.of("authenticated",true);
    }
    @GetMapping("/auth/me") public Map<String,Object> me(){return auth.me();}
    @PostMapping("/auth/reauth") public Map<String,Object> reauth(@Valid @RequestBody Reauth body){auth.reauth(body.password());return Map.of("validForSeconds",300);}
    @PostMapping("/auth/logout") public Map<String,Object> logout(HttpServletResponse res){auth.logout();cookie(res,"",0);return Map.of("loggedOut",true);}
    @GetMapping("/auth/sessions") public List<Map<String,Object>> sessions(){return s.db.queryForList("SELECT id,created_at,expires_at,user_agent,true AS authenticated FROM admin_session WHERE admin_id=? ORDER BY created_at DESC LIMIT 100",Actor.current().id());}
    @DeleteMapping("/auth/sessions/{id}") public Map<String,Object> revoke(@PathVariable UUID id){
        Actor a=Actor.current();int deleted=s.db.update("DELETE FROM admin_session WHERE id=? AND admin_id=?",id,a.id());audit.add(a.username(),"auth.session.revoke",id.toString(),"success",Map.of("count",deleted));return Map.of("revoked",deleted>0);
    }
    private void cookie(HttpServletResponse res,String token,long maxAge){res.addHeader(HttpHeaders.SET_COOKIE,ResponseCookie.from(SessionFilter.cookieName(),token).httpOnly(true).secure(!Config.local()).path("/").sameSite("Strict").maxAge(maxAge).build().toString());}
}
