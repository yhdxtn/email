package sbs.astrogate.mail.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import sbs.astrogate.mail.core.Config;
import sbs.astrogate.mail.core.Crypto;
import sbs.astrogate.mail.service.Store;

public class SessionFilter extends OncePerRequestFilter {
    private final Store s;private final ClientIpResolver clientIps;
    public SessionFilter(Store s,ClientIpResolver clientIps){this.s=s;this.clientIps=clientIps;}
    public static String cookieName(){return Config.local()?"AGSESSION":"__Host-AGSESSION";}
    @Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain)throws ServletException,IOException{
        String id=UUID.randomUUID().toString();req.setAttribute("requestId",id);res.setHeader("X-Request-ID",id);
        res.setHeader("Cache-Control","no-store");
        var ips=Config.set("ADMIN_SOURCE_IPS").stream().map(ClientIpResolver::normalize).collect(java.util.stream.Collectors.toUnmodifiableSet());
        String clientIp=clientIps.resolve(req);
        if(!ips.isEmpty()&&!ips.contains(clientIp)){deny(res,403,"SOURCE_DENIED",id);return;}
        if(!List.of("GET","HEAD","OPTIONS").contains(req.getMethod())){
            String origin=req.getHeader("Origin");
            if(origin!=null&&!origin.equals(Config.origin())){deny(res,403,"ORIGIN_DENIED",id);return;}
            long length=req.getContentLengthLong();
            if(length>5L*1024*1024){deny(res,413,"REQUEST_TOO_LARGE",id);return;}
        }
        String token=null;
        if(req.getCookies()!=null)for(var cookie:req.getCookies())if(cookie.getName().equals(cookieName()))token=cookie.getValue();
        if(token!=null&&token.matches("[A-Za-z0-9_-]{43}")){
            var rows=s.db.queryForList("SELECT a.id,a.username,a.role,s.id AS session_id FROM admin_session s JOIN admin_user a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>now() AND a.active=true",Crypto.sha256(token));
            if(!rows.isEmpty()){
                var r=rows.getFirst();
                var actor=new Actor((UUID)r.get("id"),r.get("username").toString(),r.get("role").toString(),(UUID)r.get("session_id"));
                var authorities=List.of(new SimpleGrantedAuthority("ROLE_"+actor.role()));
                SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(actor,null,authorities));
            }
        }
        try{chain.doFilter(req,res);}finally{SecurityContextHolder.clearContext();}
    }
    private void deny(HttpServletResponse res,int status,String code,String id)throws IOException{
        res.setStatus(status);res.setContentType("application/json");s.json.writeValue(res.getOutputStream(),Map.of("code",code,"message","请求被安全策略拒绝","requestId",id));
    }
}
