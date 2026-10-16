package sbs.astrogate.mail.api;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import sbs.astrogate.mail.core.*;
import sbs.astrogate.mail.security.*;
import sbs.astrogate.mail.service.*;
import static sbs.astrogate.mail.api.ApiError.fail;

@RestController
@RequestMapping("/api/v1")
@PreAuthorize("hasAnyRole('Owner','MailAdmin','DnsAdmin','Operator','Auditor')")
public class DnsController {
    private final Store s;private final DnsService dns;private final Crypto crypto;private final AuthService auth;private final Audit audit;
    public DnsController(Store s,DnsService dns,Crypto crypto,AuthService auth,Audit audit){this.s=s;this.dns=dns;this.crypto=crypto;this.auth=auth;this.audit=audit;}
    public record Domain(@NotBlank String name,@NotBlank String mailHost,@NotBlank String publicIpv4,@Size(max=80) String registrar,@NotBlank String dkimSelector,@Size(max=8192) String dkimPublic,@NotBlank String spf,@NotBlank String dmarc,@Min(60) @Max(86400) int ttl,UUID nodeId){}
    public record Provider(@NotBlank String provider,@Size(max=32) String zoneId,@Size(max=256) String token){}
    public record Confirm(@NotBlank String confirmation){}
    @GetMapping("/domains") public List<Map<String,Object>> list(){return s.db.queryForList("SELECT d.*,p.provider,p.zone_id,(p.secret_cipher IS NOT NULL) AS token_configured FROM mail_domain d JOIN dns_provider_config p ON p.domain_id=d.id ORDER BY d.name LIMIT 100");}
    @PostMapping("/domains") @PreAuthorize("hasAnyRole('Owner','MailAdmin')") @Transactional public Map<String,Object> create(@Valid @RequestBody Domain body){
        validate(body);UUID id=UUID.randomUUID();s.db.update("INSERT INTO mail_domain(id,name,mail_host,public_ipv4,registrar,dkim_selector,dkim_public,spf,dmarc,ttl,node_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",id,body.name(),body.mailHost(),body.publicIpv4(),body.registrar()==null?"":body.registrar(),body.dkimSelector(),body.dkimPublic()==null?"":body.dkimPublic(),body.spf(),body.dmarc(),body.ttl(),body.nodeId());
        s.db.update("INSERT INTO dns_provider_config(domain_id,provider) VALUES(?,'manual')",id);audit.add(Actor.current().username(),"domain.create",body.name(),"success",Map.of("provider","manual"));return Map.of("id",id,"provider","manual","dnsChanged",false);
    }
    @PutMapping("/domains/{id}") @PreAuthorize("hasAnyRole('Owner','MailAdmin','DnsAdmin')") @Transactional public Map<String,Object> update(@PathVariable UUID id,@Valid @RequestBody Domain body){
        validate(body);var old=s.one("SELECT name,node_id FROM mail_domain WHERE id=? FOR UPDATE",id);
        if(!body.name().equals(old.get("name"))||!java.util.Objects.equals(body.nodeId(),old.get("node_id")))throw fail(409,"IMMUTABLE_DOMAIN_BINDING","创建后域名及节点绑定不可在此修改");
        s.db.update("UPDATE mail_domain SET mail_host=?,public_ipv4=?,registrar=?,dkim_selector=?,dkim_public=?,spf=?,dmarc=?,ttl=? WHERE id=?",body.mailHost(),body.publicIpv4(),body.registrar()==null?"":body.registrar(),body.dkimSelector(),body.dkimPublic()==null?"":body.dkimPublic(),body.spf(),body.dmarc(),body.ttl(),id);audit.add(Actor.current().username(),"domain.update",body.name(),"success",Map.of());return Map.of("saved",true,"dnsChanged",false);
    }
    private void validate(Domain body){DnsRules.desired(body.name(),body.mailHost(),body.publicIpv4(),body.dkimSelector(),body.dkimPublic(),body.spf(),body.dmarc(),body.ttl());if(body.nodeId()!=null)s.one("SELECT id FROM mail_node WHERE id=?",body.nodeId());}
    @PutMapping("/domains/{id}/dns/provider") @PreAuthorize("hasAnyRole('Owner','DnsAdmin')") @Transactional public Map<String,Object> provider(@PathVariable UUID id,@Valid @RequestBody Provider body){
        auth.requireFresh();if(!java.util.Set.of("manual","cloudflare").contains(body.provider()))throw new IllegalArgumentException("Unsupported provider");s.one("SELECT id FROM mail_domain WHERE id=?",id);
        String token=null,zone=null;if(body.provider().equals("cloudflare")){zone=Checks.zone(body.zoneId());if(body.token()==null||!body.token().matches("[A-Za-z0-9_-]{20,256}"))throw new IllegalArgumentException("Invalid token");token=crypto.seal("dns:"+id,body.token());}
        s.db.update("UPDATE dns_provider_config SET provider=?,zone_id=?,secret_cipher=?,updated_at=now() WHERE domain_id=?",body.provider(),zone,token,id);audit.add(Actor.current().username(),"dns.provider.configure",id.toString(),"success",Map.of("provider",body.provider()));return Map.of("provider",body.provider(),"tokenConfigured",token!=null);
    }
    @GetMapping("/domains/{id}/dns/desired") public Map<String,Object> desired(@PathVariable UUID id){return Map.of("records",dns.desired(id),"websiteRecordsProtected",true,"optionalClientDiscovery","autoconfig/autodiscover 仅提供说明，未自动配置");}
    @PostMapping("/domains/{id}/dns/check") @PreAuthorize("hasAnyRole('Owner','MailAdmin','DnsAdmin','Operator')") public Map<String,Object> check(@PathVariable UUID id){return dns.check(id);}
    @PostMapping("/domains/{id}/dns/plan") public Map<String,Object> plan(@PathVariable UUID id){return dns.plan(id);}
    @GetMapping("/dns/plans") public List<Map<String,Object>> plans(){return s.db.queryForList("SELECT id,domain_id,provider,state,changes,created_at,expires_at FROM dns_plan ORDER BY created_at DESC LIMIT 100");}
    @GetMapping("/dns/plans/{id}") public Map<String,Object> planDetails(@PathVariable UUID id){return s.one("SELECT id,domain_id,provider,state,before_records,desired_records,after_records,changes,created_at,expires_at FROM dns_plan WHERE id=?",id);}
    @PostMapping("/dns/plans/{id}/apply") public Map<String,Object> apply(@PathVariable UUID id,@Valid @RequestBody Confirm body){return dns.execute(id,body.confirmation(),false);}
    @PostMapping("/dns/plans/{id}/rollback") public Map<String,Object> rollback(@PathVariable UUID id,@Valid @RequestBody Confirm body){return dns.execute(id,body.confirmation(),true);}
}
