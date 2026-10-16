package sbs.astrogate.mail.api;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import sbs.astrogate.mail.core.*;
import sbs.astrogate.mail.security.*;
import sbs.astrogate.mail.service.*;
import static sbs.astrogate.mail.api.ApiError.fail;

@RestController
@RequestMapping("/api/v1")
public class ControlController {
    private final Store s;private final Audit audit;private final Plans plans;private final Jobs jobs;private final AgentClient agent;
    public ControlController(Store s,Audit audit,Plans plans,Jobs jobs,AgentClient agent){this.s=s;this.audit=audit;this.plans=plans;this.jobs=jobs;this.agent=agent;}
    public record Node(@NotBlank @Size(max=80) String name,@NotBlank @Size(max=64) String instanceId){}
    public record Confirm(@NotBlank @Size(max=300) String confirmation){}
    public record Settings(@NotBlank @Size(max=80) String organization,@NotBlank String timezone,@Size(max=254) String alertRecipient){}
    @GetMapping("/overview") @PreAuthorize("hasAnyRole('Owner','MailAdmin','DnsAdmin','Operator','Auditor')") public Map<String,Object> overview(){
        return Map.of("domains",s.db.queryForObject("SELECT count(*) FROM mail_domain",Long.class),"mailboxes",s.db.queryForObject("SELECT count(*) FROM mailbox WHERE state<>'deleted'",Long.class),"pendingTasks",s.db.queryForObject("SELECT count(*) FROM task WHERE status IN ('queued','running')",Long.class),"failedTasks",s.db.queryForObject("SELECT count(*) FROM task WHERE status IN ('failed','unknown') AND created_at>now()-interval '24 hours'",Long.class),"nodes",s.db.queryForList("SELECT id,name,status,readonly,last_seen,CASE WHEN last_seen IS NULL OR last_seen<now()-interval '10 minutes' THEN true ELSE false END AS stale FROM mail_node ORDER BY name"),"checks",latestChecks(),"alerts",s.db.queryForList("SELECT id,message,state,last_seen,silenced_until FROM alert WHERE state='open' ORDER BY last_seen DESC LIMIT 20"),"externalDelivery","requires_manual_confirmation","releaseGate","NOT_PRODUCTION_ACCEPTED");
    }
    @GetMapping("/nodes") @PreAuthorize("hasAnyRole('Owner','MailAdmin','Operator','Auditor')") public List<Map<String,Object>> nodes(){return s.db.queryForList("SELECT id,name,instance_id,readonly,status,inventory,last_seen FROM mail_node ORDER BY name LIMIT 100");}
    @PostMapping("/nodes") @PreAuthorize("hasRole('Owner')") @Transactional public Map<String,Object> register(@Valid @RequestBody Node body){
        if(!body.instanceId().matches("[a-zA-Z0-9_-]{8,64}")||!body.instanceId().equals(Config.env("AGENT_INSTANCE_ID","")))throw fail(400,"INSTANCE_NOT_BOUND","实例 ID 必须与部署级 Agent 配置一致");
        UUID id=UUID.randomUUID();s.db.update("INSERT INTO mail_node(id,name,instance_id) VALUES(?,?,?)",id,Checks.text(body.name(),80),body.instanceId());audit.add(Actor.current().username(),"node.register",id.toString(),"readonly",Map.of("readonly",true));return Map.of("id",id,"readonly",true);
    }
    @PostMapping("/nodes/{id}/scan") @PreAuthorize("hasAnyRole('Owner','MailAdmin','Operator')") public Map<String,Object> scan(@PathVariable UUID id){
        try{var result=agent.call(id,UUID.randomUUID().toString(),"health.read",Map.of());s.db.update("UPDATE mail_node SET inventory=?::jsonb,status='reachable',last_seen=now() WHERE id=?",s.encode(result),id);audit.add(Actor.current().username(),"node.scan",id.toString(),"success",Map.of("readonly",true));return result;}
        catch(ApiError.Failure e){s.db.update("UPDATE mail_node SET status='offline' WHERE id=?",id);throw e;}
    }
    @PostMapping("/nodes/{id}/enable-management-plan") @PreAuthorize("hasRole('Owner')") public Map<String,Object> management(@PathVariable UUID id){
        var result=scan(id);if(!Boolean.TRUE.equals(result.get("writeEnabled")))throw fail(409,"AGENT_READ_ONLY","Agent 尚未通过本机人工审批并开启写权限");
        return plans.create("node.enable_management",id,id,Map.of(),Map.of("nodeId",id,"effect","启用已获本机审批的受限管理；不会重装服务或改动 DNS"),"ENABLE MANAGEMENT "+id);
    }
    @GetMapping("/tasks") @PreAuthorize("hasAnyRole('Owner','MailAdmin','DnsAdmin','Operator','Auditor')") public List<Map<String,Object>> tasks(){return s.db.queryForList("SELECT id,kind,node_id,entity_id,status,error_code,attempts,result,created_at,started_at,finished_at FROM task ORDER BY created_at DESC LIMIT 100");}
    @GetMapping("/tasks/{id}") @PreAuthorize("hasAnyRole('Owner','MailAdmin','DnsAdmin','Operator','Auditor')") public Map<String,Object> task(@PathVariable UUID id){return s.one("SELECT id,kind,node_id,entity_id,status,error_code,attempts,result,created_at,started_at,finished_at FROM task WHERE id=?",id);}
    @PostMapping("/plans/{id}/confirm") @ResponseStatus(HttpStatus.ACCEPTED) public Map<String,Object> confirm(@PathVariable UUID id,@Valid @RequestBody Confirm body,@RequestHeader("Idempotency-Key") String key){
        String kind=plans.kind(id),role=Actor.current().role();
        boolean permitted=role.equals("Owner")||(role.equals("MailAdmin")&&(kind.startsWith("mailbox.")||kind.startsWith("mail.queue.")||kind.equals("mail.send")));
        if(!permitted)throw fail(403,"FORBIDDEN","无权确认此类计划");return plans.confirm(id,body.confirmation(),key);
    }
    @GetMapping("/settings") @PreAuthorize("hasAnyRole('Owner','Operator','Auditor')") public Map<String,Object> settings(){return Map.of("settings",s.map(s.one("SELECT value FROM settings WHERE id=1").get("value")),"smtpConfigured",!Config.env("SMTP_HOST","").isBlank(),"testRecipients",Config.set("TEST_RECIPIENTS"),"agentConfigured",agent.configured(),"websiteConnector","disabled","backupScope","node_profiles_only","networkSettings","deployment_config_only");}
    @PutMapping("/settings") @PreAuthorize("hasRole('Owner')") @Transactional public Map<String,Object> settings(@Valid @RequestBody Settings body){java.time.ZoneId.of(body.timezone());if(body.alertRecipient()!=null&&!body.alertRecipient().isBlank())Checks.email(body.alertRecipient());s.db.update("UPDATE settings SET value=?::jsonb,updated_at=now() WHERE id=1",s.encode(body));audit.add(Actor.current().username(),"settings.update","organization","success",Map.of());return Map.of("saved",true,"notifications","in_app_only");}
    @GetMapping("/health/checks") @PreAuthorize("hasAnyRole('Owner','MailAdmin','DnsAdmin','Operator','Auditor')") public List<Map<String,Object>> checks(){return latestChecks();}
    private List<Map<String,Object>> latestChecks(){return s.db.queryForList("SELECT DISTINCT ON (name,node_id,domain_id) id,name,node_id,domain_id,CASE WHEN checked_at<now()-interval '10 minutes' THEN 'unknown' ELSE state END AS state,detail,source,latency_ms,checked_at FROM monitor_check ORDER BY name,node_id,domain_id,checked_at DESC LIMIT 200");}
    @PostMapping("/health/checks/run") @PreAuthorize("hasAnyRole('Owner','MailAdmin','Operator')") @ResponseStatus(HttpStatus.ACCEPTED) public Map<String,Object> check(@RequestParam UUID nodeId,@RequestHeader("Idempotency-Key") String key){s.one("SELECT id FROM mail_node WHERE id=?",nodeId);return jobs.submit(key,"diagnostics.read",nodeId,null,Map.of());}
    @GetMapping("/audit/events") @PreAuthorize("hasAnyRole('Owner','Auditor')") public List<Map<String,Object>> audit(@RequestParam(defaultValue="0") long before){return before==0?s.db.queryForList("SELECT id,actor,action,target,outcome,request_id,summary,created_at FROM audit_event ORDER BY id DESC LIMIT 100"):s.db.queryForList("SELECT id,actor,action,target,outcome,request_id,summary,created_at FROM audit_event WHERE id<? ORDER BY id DESC LIMIT 100",before);}
    @GetMapping("/website-users") @PreAuthorize("hasAnyRole('Owner','WebsiteUserAdmin','Auditor')") public Map<String,Object> website(){return Map.of("enabled",false,"items",List.of(),"reason","未配置网站用户连接器；本版本不写入现有网站数据库，也不自动开通邮箱");}
    @GetMapping("/alerts") @PreAuthorize("hasAnyRole('Owner','MailAdmin','Operator','Auditor')") public List<Map<String,Object>> alerts(){return s.db.queryForList("SELECT id,message,state,first_seen,last_seen,silenced_until,recovered_at FROM alert ORDER BY last_seen DESC LIMIT 100");}
    @PostMapping("/alerts/{id}/silence") @PreAuthorize("hasAnyRole('Owner','Operator')") public Map<String,Object> silence(@PathVariable UUID id){s.db.update("UPDATE alert SET silenced_until=now()+interval '1 hour' WHERE id=?",id);audit.add(Actor.current().username(),"alert.silence",id.toString(),"success",Map.of());return Map.of("silencedForSeconds",3600);}
}
