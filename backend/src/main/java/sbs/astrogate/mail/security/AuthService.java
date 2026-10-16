package sbs.astrogate.mail.security;

import java.sql.Timestamp;
import java.util.Map;
import java.util.UUID;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sbs.astrogate.mail.core.Checks;
import sbs.astrogate.mail.core.Config;
import sbs.astrogate.mail.core.Crypto;
import sbs.astrogate.mail.service.Audit;
import sbs.astrogate.mail.service.Store;
import static sbs.astrogate.mail.api.ApiError.fail;

@Service
public class AuthService {
    private final Store s;private final Crypto crypto;private final PasswordEncoder passwords;private final Audit audit;private final RateLimiter rate;
    private final String dummy;
    public AuthService(Store s,Crypto crypto,PasswordEncoder passwords,Audit audit,RateLimiter rate){this.s=s;this.crypto=crypto;this.passwords=passwords;this.audit=audit;this.rate=rate;dummy=passwords.encode(Crypto.token());}
    public boolean needsSetup(){return !Boolean.TRUE.equals(s.db.queryForObject("SELECT initialized FROM system_setup WHERE id=1",Boolean.class));}
    @Transactional
    public void setup(String token,String username,String password,String ip){
        rate.check("setup:"+crypto.fingerprint(ip),8,900);
        var row=s.one("SELECT initialized FROM system_setup WHERE id=1 FOR UPDATE");
        if(Boolean.TRUE.equals(row.get("initialized")))throw fail(409,"SETUP_CLOSED","初始化入口已经关闭");
        if(!Crypto.equal(Config.secret("APP_SETUP_TOKEN"),token))throw fail(403,"SETUP_TOKEN_INVALID","初始化凭据无效");
        username(username);Checks.password(password);UUID id=UUID.randomUUID();
        s.db.update("INSERT INTO admin_user(id,username,password_hash,role) VALUES(?,?,?,'Owner')",id,username,passwords.encode(password));
        s.db.update("UPDATE system_setup SET initialized=true WHERE id=1");
        audit.add(username,"setup.initialize",id.toString(),"success",Map.of("role","Owner"));
    }
    @Transactional
    public String login(String username,String password,String ip,String userAgent){
        rate.check("login-ip:"+crypto.fingerprint(ip),20,900);
        rate.check("login-user:"+crypto.fingerprint(username==null?"":username),10,900);
        var rows=s.db.queryForList("SELECT id,username,password_hash,active FROM admin_user WHERE username=?",username);
        String hash=rows.isEmpty()?dummy:rows.getFirst().get("password_hash").toString();
        boolean ok=password!=null&&password.length()<=256&&passwords.matches(password,hash);
        if(!ok||rows.isEmpty()||!Boolean.TRUE.equals(rows.getFirst().get("active")))throw fail(401,"LOGIN_FAILED","用户名或密码不正确");
        var row=rows.getFirst();String token=Crypto.token();UUID id=(UUID)row.get("id");
        s.db.update("DELETE FROM admin_session WHERE admin_id=? AND mfa_verified=false",id);
        s.db.update("INSERT INTO admin_session(token_hash,id,admin_id,mfa_verified,expires_at,reauth_at,ip_hash,user_agent) VALUES(?,?,?,true,now()+interval '8 hours',now(),?,?)",Crypto.sha256(token),UUID.randomUUID(),id,crypto.fingerprint(ip),safeAgent(userAgent));
        audit.add(username,"auth.login",id.toString(),"success",Map.of());return token;
    }
    @Transactional
    public void reauth(String password){
        Actor a=Actor.current();
        rate.check("reauth:"+a.id(),8,300);
        var row=s.one("SELECT password_hash FROM admin_user WHERE id=?",a.id());
        if(password==null||password.length()>256||!passwords.matches(password,row.get("password_hash").toString()))throw fail(403,"REAUTH_FAILED","重新认证失败");
        s.db.update("UPDATE admin_session SET reauth_at=now() WHERE id=?",a.sessionId());
        audit.add(a.username(),"auth.reauthenticate",a.sessionId().toString(),"success",Map.of());
    }
    public void requireFresh(){
        Actor a=Actor.current();var r=s.one("SELECT reauth_at FROM admin_session WHERE id=? AND expires_at>now()",a.sessionId());
        if(r.get("reauth_at")==null||((Timestamp)r.get("reauth_at")).toInstant().isBefore(java.time.Instant.now().minusSeconds(300)))throw fail(403,"REAUTH_REQUIRED","该操作要求在最近 5 分钟内重新输入管理员密码");
    }
    public void logout(){Actor a=Actor.current();s.db.update("DELETE FROM admin_session WHERE id=?",a.sessionId());audit.add(a.username(),"auth.logout",a.sessionId().toString(),"success",Map.of());}
    public Map<String,Object> me(){Actor a=Actor.current();return s.one("SELECT id,username,role FROM admin_user WHERE id=?",a.id());}
    private static String safeAgent(String value){String clean=value==null?"":value.replaceAll("[\\p{Cntrl}]","");return clean.substring(0,Math.min(160,clean.length()));}
    public static String username(String value){if(value==null||!value.matches("[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}"))throw new IllegalArgumentException("Invalid username");return value;}
}
