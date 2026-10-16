package sbs.astrogate.mail.service;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.apache.commons.codec.digest.Sha2Crypt;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sbs.astrogate.mail.core.*;
import sbs.astrogate.mail.security.Actor;
import static sbs.astrogate.mail.api.ApiError.fail;

@Service
@PreAuthorize("hasAnyRole('Owner','MailAdmin')")
public class MailService {
    private final Store s;private final Jobs jobs;private final Plans plans;private final Crypto crypto;private final Audit audit;private final sbs.astrogate.mail.security.AuthService auth;
    public MailService(Store s,Jobs jobs,Plans plans,Crypto crypto,Audit audit,sbs.astrogate.mail.security.AuthService auth){this.s=s;this.jobs=jobs;this.plans=plans;this.crypto=crypto;this.audit=audit;this.auth=auth;}
    public Map<String,Object> writableNode(UUID id){
        var row=s.one("SELECT id,readonly,status,last_seen FROM mail_node WHERE id=?",id);
        if(Boolean.TRUE.equals(row.get("readonly")))throw fail(409,"NODE_READ_ONLY","节点处于只读导入模式，请先在克隆环境完成适配验收");return row;
    }
    private String passwordHash(String address,String password,String key){
        Checks.password(password);Jobs.validateKey(key);
        String salt=crypto.fingerprint(Actor.current().id()+"\n"+address+"\n"+key).substring(0,16);
        return "{SHA512-CRYPT}"+Sha2Crypt.sha512Crypt(password.getBytes(StandardCharsets.UTF_8),"$6$rounds=100000$"+salt+"$");
    }
    @Transactional
    public Map<String,Object> createMailbox(UUID domainId,String address,String password,long quota,String key){
        auth.requireFresh();
        Checks.email(address);Checks.quota(quota);var domain=s.one("SELECT id,name,node_id FROM mail_domain WHERE id=?",domainId);
        if(!address.endsWith("@"+domain.get("name")))throw fail(400,"DOMAIN_MISMATCH","邮箱地址不属于选定域名");
        if(domain.get("node_id")==null)throw fail(409,"NODE_REQUIRED","请先关联邮件节点");UUID node=(UUID)domain.get("node_id");writableNode(node);
        var params=Map.<String,Object>of("address",address,"quotaBytes",quota,"passwordHash",passwordHash(address,password,key));
        var existing=jobs.existing(key,"mailbox.create",node,params);if(existing!=null)return existing;
        UUID id=UUID.randomUUID();s.db.update("INSERT INTO mailbox(id,domain_id,node_id,address,quota_bytes) VALUES(?,?,?,?,?)",id,domainId,node,address,quota);
        return jobs.submit(key,"mailbox.create",node,id,params);
    }
    @Transactional
    public Map<String,Object> action(UUID id,String action,String password,Long quota,String key){
        auth.requireFresh();
        var row=s.one("SELECT * FROM mailbox WHERE id=? FOR UPDATE",id);UUID node=(UUID)row.get("node_id");writableNode(node);
        String address=row.get("address").toString();Map<String,Object> params=new HashMap<>();params.put("address",address);
        String method=switch(action){case "disable"->"mailbox.disable";case "enable"->"mailbox.enable";case "password-reset"->"mailbox.password_reset";case "quota"->"mailbox.quota";default->throw new IllegalArgumentException("Unknown mailbox action");};
        if(action.equals("password-reset"))params.put("passwordHash",passwordHash(address,password,key));
        if(action.equals("quota")){if(quota==null)throw new IllegalArgumentException("quota missing");params.put("quotaBytes",Checks.quota(quota));}
        var existing=jobs.existing(key,method,node,params);if(existing!=null)return existing;
        if(s.db.queryForObject("SELECT count(*) FROM task WHERE entity_id=? AND status IN ('queued','running')",Long.class,id)>0)throw fail(409,"OPERATION_IN_PROGRESS","该邮箱已有执行中的任务");
        if(row.get("state").equals("pending")||row.get("state").equals("failed")||row.get("state").equals("unknown"))throw fail(409,"MAILBOX_NOT_CONFIRMED","邮箱状态尚未由节点确认，请先只读同步核对");
        return jobs.submit(key,method,node,id,params);
    }
    @Transactional
    public Map<String,Object> deletePlan(UUID id){
        auth.requireFresh();
        var row=s.one("SELECT * FROM mailbox WHERE id=?",id);writableNode((UUID)row.get("node_id"));
        if(s.db.queryForObject("SELECT count(*) FROM task WHERE entity_id=? AND status IN ('queued','running')",Long.class,id)>0)throw fail(409,"OPERATION_IN_PROGRESS","请先等待现有邮箱任务结束");
        String address=row.get("address").toString();
        return plans.create("mailbox.soft_delete",(UUID)row.get("node_id"),id,Map.of("address",address),Map.of("address",address,"effect","停用登录并标记待清理；保留 Maildir，不物理删除；可恢复","cleanup","自动物理清理未启用"),"DELETE "+address);
    }
    @Transactional
    public Map<String,Object> createAlias(UUID domainId,String address,String destination,String key){
        auth.requireFresh();
        Checks.email(address);Checks.email(destination);if(address.equals(destination))throw fail(400,"ALIAS_LOOP","别名不能指向自身");
        var domain=s.one("SELECT name,node_id FROM mail_domain WHERE id=?",domainId);UUID node=(UUID)domain.get("node_id");if(node==null)throw fail(409,"NODE_REQUIRED","请先关联节点");writableNode(node);
        if(!address.endsWith("@"+domain.get("name")))throw fail(400,"DOMAIN_MISMATCH","别名不属于指定域");
        var params=Map.<String,Object>of("address",address,"destination",destination);var old=jobs.existing(key,"alias.create",node,params);if(old!=null)return old;
        if(s.db.queryForObject("SELECT count(*) FROM mailbox WHERE address=?",Long.class,address)>0)throw fail(409,"ADDRESS_IN_USE","该地址已是邮箱，不能再定义别名");
        // Deliberately reject alias chains: one-hop local mailbox or explicitly allowed external domain only.
        boolean local=s.db.queryForObject("SELECT count(*) FROM mailbox WHERE address=? AND state='active'",Long.class,destination)>0;
        if(!local&&!Config.set("FORWARD_ALLOWED_DOMAINS").contains(destination.substring(destination.indexOf('@')+1)))throw fail(400,"FORWARD_NOT_ALLOWED","目标必须是已启用的真实邮箱，或部署级允许的外部转发域；不支持别名链");
        UUID id=UUID.randomUUID();s.db.update("INSERT INTO mailbox_alias(id,node_id,domain_id,address,destination) VALUES(?,?,?,?,?)",id,node,domainId,address,destination);
        return jobs.submit(key,"alias.create",node,id,params);
    }
    @Transactional
    public Map<String,Object> deleteAlias(UUID id,String key){
        auth.requireFresh();
        var row=s.one("SELECT * FROM mailbox_alias WHERE id=? FOR UPDATE",id);writableNode((UUID)row.get("node_id"));
        return jobs.submit(key,"alias.delete",(UUID)row.get("node_id"),id,Map.of("address",row.get("address")));
    }
}
