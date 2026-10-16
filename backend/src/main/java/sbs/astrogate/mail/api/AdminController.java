package sbs.astrogate.mail.api;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import sbs.astrogate.mail.core.Checks;
import sbs.astrogate.mail.security.*;
import sbs.astrogate.mail.service.*;
import static sbs.astrogate.mail.api.ApiError.fail;

@RestController
@RequestMapping("/api/v1/admins")
@PreAuthorize("hasRole('Owner')")
public class AdminController {
    private final Store s;private final AuthService auth;private final Audit audit;private final PasswordEncoder passwords;
    public AdminController(Store s,AuthService auth,Audit audit,PasswordEncoder passwords){this.s=s;this.auth=auth;this.audit=audit;this.passwords=passwords;}
    public record Create(@NotBlank @Size(max=64) String username,@NotBlank @Size(max=256) String password,@NotBlank String role){}
    public record Update(@NotBlank String role,boolean active,@NotBlank String confirmation){}
    private static final Set<String> ROLES=Set.of("Owner","MailAdmin","DnsAdmin","Operator","Auditor","WebsiteUserAdmin");
    @GetMapping public List<Map<String,Object>> list(){return s.db.queryForList("SELECT id,username,role,active,created_at FROM admin_user ORDER BY created_at LIMIT 100");}
    @PostMapping @Transactional public Map<String,Object> create(@Valid @RequestBody Create body){
        auth.requireFresh();if(!ROLES.contains(body.role()))throw new IllegalArgumentException("Invalid role");UUID id=UUID.randomUUID();
        s.db.update("INSERT INTO admin_user(id,username,password_hash,role) VALUES(?,?,?,?)",id,AuthService.username(body.username()),passwords.encode(Checks.password(body.password())),body.role());
        audit.add(Actor.current().username(),"admin.create",id.toString(),"success",Map.of("role",body.role()));return Map.of("id",id,"loginRequired",true);
    }
    @PutMapping("/{id}") @Transactional public Map<String,Object> update(@PathVariable UUID id,@Valid @RequestBody Update body){
        auth.requireFresh();if(!ROLES.contains(body.role())||!body.confirmation().equals("UPDATE "+id))throw fail(400,"CONFIRMATION_REQUIRED","确认文字不匹配");
        s.one("SELECT id FROM system_setup WHERE id=1 FOR UPDATE");var row=s.one("SELECT role,active FROM admin_user WHERE id=? FOR UPDATE",id);
        if(row.get("role").equals("Owner")&&Boolean.TRUE.equals(row.get("active"))&&(!body.active()||!body.role().equals("Owner"))&&s.db.queryForObject("SELECT count(*) FROM admin_user WHERE role='Owner' AND active=true",Long.class)<=1)throw fail(409,"LAST_OWNER","不能停用或降级最后一个 Owner");
        s.db.update("UPDATE admin_user SET role=?,active=? WHERE id=?",body.role(),body.active(),id);s.db.update("DELETE FROM admin_session WHERE admin_id=?",id);
        audit.add(Actor.current().username(),"admin.update",id.toString(),"success",Map.of("role",body.role(),"state",body.active()?"active":"disabled"));return Map.of("updated",true,"sessionsRevoked",true);
    }
}
