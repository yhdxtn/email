package sbs.astrogate.mail.service;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import sbs.astrogate.mail.core.*;
import sbs.astrogate.mail.dns.*;
import sbs.astrogate.mail.security.*;
import static sbs.astrogate.mail.api.ApiError.fail;

@Service
public class DnsService {
    private final Store s;private final Crypto crypto;private final CloudflareDnsProvider cf;private final DnsLookup lookup;private final AuthService auth;private final Audit audit;private final TransactionTemplate tx;
    public DnsService(Store s,Crypto crypto,CloudflareDnsProvider cf,DnsLookup lookup,AuthService auth,Audit audit,PlatformTransactionManager manager){this.s=s;this.crypto=crypto;this.cf=cf;this.lookup=lookup;this.auth=auth;this.audit=audit;tx=new TransactionTemplate(manager);}
    public List<DnsRules.Record> desired(UUID domainId){return desired(s.one("SELECT * FROM mail_domain WHERE id=?",domainId));}
    private List<DnsRules.Record> desired(Map<String,Object>d){return DnsRules.desired(d.get("name").toString(),d.get("mail_host").toString(),d.get("public_ipv4").toString(),d.get("dkim_selector").toString(),d.get("dkim_public").toString(),d.get("spf").toString(),d.get("dmarc").toString(),((Number)d.get("ttl")).intValue());}
    private List<DnsRules.Record> records(Object json){return Arrays.asList(s.decode(json,DnsRules.Record[].class));}
    public Map<String,Object> check(UUID domainId){
        var domain=s.one("SELECT * FROM mail_domain WHERE id=?",domainId);String name=domain.get("name").toString();var expected=desired(domain);List<Map<String,Object>> checks=new ArrayList<>();
        for(var record:expected){var result=new LinkedHashMap<>(lookup.query(record.name(),record.type()));var values=(List<?>)result.get("values");String value=record.type().equals("MX")?record.priority()+" "+record.content():record.content();
            boolean found=values.stream().map(Object::toString).map(DnsRules::normalize).map(v->v.replaceAll("\\.$","")).anyMatch(v->v.equals(value));
            String state=result.get("state").equals("unknown")?"unknown":found?"healthy":"failed";result.put("expected",value);result.put("state",state);checks.add(result);
            s.db.update("INSERT INTO monitor_check(domain_id,name,state,detail,source,latency_ms) VALUES(?,?,?,?::jsonb,?,?)",domainId,"dns."+record.type()+"."+record.name(),state,s.encode(result),"system_recursive_resolver",result.get("latencyMs"));
        }
        if(domain.get("dkim_public").toString().isBlank())checks.add(Map.of("name",domain.get("dkim_selector")+"._domainkey."+name,"type","TXT","state","unknown","reason","未配置 DKIM 公钥，未标记通过"));
        String[] ip=domain.get("public_ipv4").toString().split("\\.");String ptr=ip[3]+"."+ip[2]+"."+ip[1]+"."+ip[0]+".in-addr.arpa";
        return Map.of("records",checks,"nameservers",lookup.authority(name),"registrar",domain.get("registrar"),"ptr",lookup.query(ptr,"PTR"),"ptrAction","由 IP/VPS 服务商管理；本系统不会自动改 PTR","propagation","仅本控制面递归解析视角，非全球传播证明","checkedAt",Instant.now().toString());
    }
    @PreAuthorize("hasAnyRole('Owner','DnsAdmin')")
    public Map<String,Object> plan(UUID domainId){
        var domain=s.one("SELECT * FROM mail_domain WHERE id=?",domainId);var config=s.one("SELECT * FROM dns_provider_config WHERE domain_id=?",domainId);var expected=desired(domain);var ns=lookup.authority(domain.get("name").toString());
        if(config.get("provider").equals("manual"))return Map.of("mode","manual","records",expected,"nameservers",ns,"canApply",false,"instruction","请在实际权威 DNS 托管商后台手工修改；不要修改网站 A 记录","spfWarning","把所有合法发信源合并为一条 SPF，不要增加第二条 SPF");
        ensureAuthority(ns);String token=secret(config);String zone=config.get("zone_id").toString();var zoneInfo=cf.zoneInfo(zone,token);
        if(!zoneInfo.get("name").equals(domain.get("name")))throw fail(409,"ZONE_MISMATCH","Zone ID 不属于该邮件域");
        var before=DnsRules.managed(cf.listRecords(zone,token),expected,domain.get("name").toString());var diff=DnsRules.diff(before,expected,domain.get("name").toString());UUID id=UUID.randomUUID();
        tx.executeWithoutResult(t->{
            s.db.update("INSERT INTO dns_plan(id,domain_id,actor_id,provider,provider_version,state,before_records,desired_records,changes,expires_at) VALUES(?,?,?,'cloudflare',?,'planned',?::jsonb,?::jsonb,?::jsonb,now()+interval '15 minutes')",id,domainId,Actor.current().id(),configVersion(config),s.encode(before),s.encode(expected),s.encode(diff));
            audit.add(Actor.current().username(),"dns.plan",domainId.toString(),"ready",Map.of("count",diff.size(),"planId",id.toString()));
        });
        return Map.of("id",id,"mode","cloudflare","canApply",true,"changes",diff,"before",before,"desired",expected,"confirmation","APPLY DNS "+id,"expiresInSeconds",900,"warning","请审核 SPF 的全部合法发信源和所有 MX；网站 A 不在变更范围内");
    }
    @PreAuthorize("hasAnyRole('Owner','DnsAdmin')")
    public Map<String,Object> execute(UUID id,String confirmation,boolean rollback){
        auth.requireFresh();Actor actor=Actor.current();String expectedText=(rollback?"ROLLBACK DNS ":"APPLY DNS ")+id;
        if(!Crypto.equal(expectedText,confirmation))throw fail(400,"CONFIRMATION_REQUIRED","确认文字不匹配");
        // State transition is committed before remote side effects; a crash leaves an explicit in-progress/unknown state.
        var prepared=tx.execute(t->{
            var p=s.one("SELECT * FROM dns_plan WHERE id=? AND actor_id=? FOR UPDATE",id,actor.id());String state=p.get("state").toString();
            if(!rollback&&state.equals("applied"))return Map.<String,Object>of("already",true);
            if(rollback&&state.equals("rolled_back"))return Map.<String,Object>of("already",true);
            if(!(rollback?state.equals("applied"):state.equals("planned")))throw fail(409,"PLAN_STATE_CONFLICT","计划正在执行、未完成或需人工核对，不能重复执行");
            if(!rollback&&((Timestamp)p.get("expires_at")).toInstant().isBefore(Instant.now()))throw fail(409,"PLAN_EXPIRED","DNS 计划已过期，请重新预览");
            var config=s.one("SELECT * FROM dns_provider_config WHERE domain_id=?",p.get("domain_id"));
            if(!configVersion(config).equals(p.get("provider_version")))throw fail(409,"PROVIDER_CHANGED","DNS provider 或凭据已变更，请重新生成计划");
            if(!rollback&&!DnsRules.fingerprint(desired((UUID)p.get("domain_id"))).equals(DnsRules.fingerprint(records(p.get("desired_records")))))throw fail(409,"DESIRED_CHANGED","期望记录已变更，请重新生成计划");
            p.put("config",config);s.db.update("UPDATE dns_plan SET state=? WHERE id=?",rollback?"rolling_back":"applying",id);return p;
        });
        if(Boolean.TRUE.equals(prepared.get("already")))return Map.of("id",id,"state",rollback?"rolled_back":"applied","reused",true);
        try{
            var domain=s.one("SELECT name FROM mail_domain WHERE id=?",prepared.get("domain_id"));String name=domain.get("name").toString();ensureAuthority(lookup.authority(name));
            var config=s.map(prepared.get("config"));String zone=config.get("zone_id").toString(),token=secret(config);
            var expected=records(prepared.get("desired_records"));var before=records(prepared.get("before_records"));
            var current=DnsRules.managed(cf.listRecords(zone,token),expected,name);
            var expectedCurrent=rollback?records(prepared.get("after_records")):before;
            if(!DnsRules.fingerprint(current).equals(DnsRules.fingerprint(expectedCurrent)))throw fail(409,"DNS_DRIFT","当前 DNS 已与快照不同，拒绝覆盖其他人的修改");
            var target=rollback?before.stream().map(DnsRules.Record::withoutId).toList():expected;
            // For rollback to an empty slot, keep slot context from the original desired set.
            var changes=rollback?rollbackDiff(current,target):DnsRules.diff(current,target,name);
            cf.applyChanges(zone,token,changes);
            var after=DnsRules.managed(cf.listRecords(zone,token),expected,name);
            if(!DnsRules.fingerprint(after).equals(DnsRules.fingerprint(target)))throw fail(409,"DNS_APPLY_UNCONFIRMED","API 返回后状态尚未匹配，需检查传播或并发变更");
            tx.executeWithoutResult(t->{s.db.update("UPDATE dns_plan SET state=?,after_records=?::jsonb WHERE id=?",rollback?"rolled_back":"applied",s.encode(after),id);audit.add(actor.username(),rollback?"dns.rollback":"dns.apply",prepared.get("domain_id").toString(),"success",Map.of("planId",id.toString(),"count",changes.size()));});
            return Map.of("id",id,"state",rollback?"rolled_back":"applied","records",after,"propagation","provider_state_only");
        }catch(Exception e){
            tx.executeWithoutResult(t->{s.db.update("UPDATE dns_plan SET state='unknown' WHERE id=?",id);audit.add(actor.username(),rollback?"dns.rollback":"dns.apply",id.toString(),"unknown",Map.of("errorCode",e instanceof sbs.astrogate.mail.api.ApiError.Failure f?f.code:"DNS_EXECUTION_UNKNOWN"));});
            if(e instanceof sbs.astrogate.mail.api.ApiError.Failure f)throw f;throw fail(502,"DNS_EXECUTION_UNKNOWN","操作结果未确认，禁止盲目重复；请查询当前 DNS");
        }
    }
    private List<DnsRules.Change> rollbackDiff(List<DnsRules.Record> current,List<DnsRules.Record> target){
        // Exact rollback removes only the previously managed records, then recreates the immutable snapshot.
        List<DnsRules.Change> result=new ArrayList<>();for(var r:current)result.add(new DnsRules.Change("delete",r,null));for(var r:target)result.add(new DnsRules.Change("create",null,r));return result;
    }
    private void ensureAuthority(List<String> ns){if(ns.isEmpty()||ns.stream().anyMatch(n->!n.toLowerCase(Locale.ROOT).replaceAll("\\.$","").endsWith(".ns.cloudflare.com")))throw fail(409,"AUTHORITY_NOT_CLOUDFLARE","实际 NS 未确认为 Cloudflare；请使用手工模式或适配实际 provider");}
    private String secret(Map<String,Object> config){if(config.get("secret_cipher")==null)throw fail(409,"DNS_TOKEN_MISSING","没有配置 DNS API Token");return crypto.open("dns:"+config.get("domain_id"),config.get("secret_cipher").toString());}
    private String configVersion(Map<String,Object> config){return crypto.fingerprint(config.get("provider")+"\n"+config.get("zone_id")+"\n"+config.get("secret_cipher"));}
}
