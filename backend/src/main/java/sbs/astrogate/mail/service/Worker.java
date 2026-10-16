package sbs.astrogate.mail.service;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import sbs.astrogate.mail.api.ApiError;
import static sbs.astrogate.mail.api.ApiError.fail;

/** One process-safe database claimant. No automatic retries after uncertain external effects. */
@Component
@ConditionalOnProperty(name="app.jobs.enabled",havingValue="true",matchIfMissing=true)
public class Worker {
    private final Store s;private final Jobs jobs;private final AgentClient agent;private final Sender sender;private final Audit audit;private final TransactionTemplate tx;
    private final AtomicBoolean busy=new AtomicBoolean();
    private static final Set<String> UNCERTAIN=Set.of("AGENT_OFFLINE_OR_TIMEOUT","AGENT_RESPONSE_TOO_LARGE","OPERATION_UNCONFIRMED","PREVIOUS_JOB_UNKNOWN","PREVIOUS_JOB_RUNNING","SMTP_RESULT_UNKNOWN","INTERNAL_ERROR");
    private static final Set<String> RPC=Set.of("mailbox.create","mailbox.disable","mailbox.enable","mailbox.password_reset","mailbox.quota","mailbox.soft_delete","alias.create","alias.delete","diagnostics.read","mail.queue.retry_allowlisted","mail.queue.delete_allowlisted","backup.create","backup.verify","backup.restore_drill");
    public Worker(Store s,Jobs jobs,AgentClient agent,Sender sender,Audit audit,PlatformTransactionManager manager){this.s=s;this.jobs=jobs;this.agent=agent;this.sender=sender;this.audit=audit;this.tx=new TransactionTemplate(manager);}
    @Scheduled(fixedDelay=1500,initialDelay=5000)
    public void tick(){
        if(!busy.compareAndSet(false,true))return;
        try{var task=jobs.claim();if(task!=null)execute(task);}finally{busy.set(false);}
    }
    /** Public for integration tests; only the scheduler passes database-claimed tasks. */
    public void execute(Map<String,Object> task){
        UUID id=(UUID)task.get("id"),node=(UUID)task.get("node_id");String kind=task.get("kind").toString();
        try{
            if(task.get("created_at") instanceof java.sql.Timestamp created && created.toInstant().isBefore(java.time.Instant.now().minusSeconds(900)))throw fail(409,"TASK_EXPIRED","排队任务已超过 15 分钟，请重新预览提交");
            var user=s.one("SELECT active,role,username FROM admin_user WHERE id=?",task.get("actor_id"));
            if(!Boolean.TRUE.equals(user.get("active"))||!permitted(user.get("role").toString(),kind))throw fail(403,"ACTOR_AUTHORIZATION_REVOKED","操作人授权已撤销");
            var params=jobs.payload(task);Map<String,Object> result;
            if(kind.equals("mail.send"))result=sender.send(id,params);
            else if(kind.equals("node.enable_management")){
                result=agent.call(node,id.toString(),"health.read",Map.of());
                if(!Boolean.TRUE.equals(result.get("writeEnabled")))throw fail(409,"AGENT_READ_ONLY","节点人工审批状态已变化");
            }else{
                if(!RPC.contains(kind))throw fail(403,"TASK_KIND_NOT_ALLOWED","未知任务方法");
                if(kind.startsWith("mailbox.")||kind.startsWith("alias.")||kind.startsWith("mail.queue.")){
                    if(Boolean.TRUE.equals(s.one("SELECT readonly FROM mail_node WHERE id=?",node).get("readonly")))throw fail(409,"NODE_READ_ONLY","节点处于只读模式");
                }
                result=agent.call(node,id.toString(),kind,params);
            }
            tx.executeWithoutResult(status->{
                applyResult(task,params,result);
                jobs.finish(id,"success",result,null);
                audit.add(user.get("username").toString(),"task.complete",id.toString(),"success",Map.of("method",kind,"taskId",id.toString()));
            });
        }catch(Exception error){
            String code=error instanceof ApiError.Failure failure?failure.code:"INTERNAL_ERROR";
            String state=UNCERTAIN.contains(code)?"unknown":"failed";
            // A non-transactional SMTP/Agent side effect may have succeeded. Never call it again blindly.
            tx.executeWithoutResult(status->{
                if(node!=null&&code.startsWith("AGENT_"))s.db.update("UPDATE mail_node SET status='offline' WHERE id=?",node);
                if(kind.startsWith("mailbox."))s.db.update("UPDATE mailbox SET state=?,updated_at=now() WHERE id=?",state,task.get("entity_id"));
                if(kind.startsWith("alias."))s.db.update("UPDATE mailbox_alias SET state=? WHERE id=?",state,task.get("entity_id"));
                if(kind.equals("mail.send"))s.db.update("UPDATE mail_send SET state=? WHERE id=?",state,id);
                if(kind.equals("backup.create")||kind.equals("backup.verify"))s.db.update("UPDATE backup SET status=? WHERE id=?",state,task.get("entity_id"));
                if(kind.equals("backup.restore_drill"))s.db.update("UPDATE restore_drill SET state=? WHERE task_id=?",state,id);
                jobs.finish(id,state,Map.of("automaticRetry",false,"reconciliationRequired",state.equals("unknown")),code);
                audit.add("worker","task.complete",id.toString(),state,Map.of("method",kind,"errorCode",code,"taskId",id.toString()));
            });
        }
    }
    static boolean permitted(String role,String kind){
        if(role.equals("Owner"))return true;
        if(role.equals("MailAdmin"))return kind.startsWith("mailbox.")||kind.startsWith("alias.")||kind.startsWith("mail.queue.")||kind.equals("mail.send")||kind.equals("diagnostics.read");
        return role.equals("Operator")&&(kind.equals("backup.create")||kind.equals("backup.verify")||kind.equals("diagnostics.read"));
    }
    private void applyResult(Map<String,Object> task,Map<String,Object> params,Map<String,Object> result){
        String kind=task.get("kind").toString();Object entity=task.get("entity_id"),node=task.get("node_id");
        if(kind.startsWith("mailbox.")){
            String state=String.valueOf(result.get("state"));if(!Set.of("active","disabled","deleted").contains(state))throw new IllegalStateException("Invalid mailbox outcome");
            long quota=((Number)result.get("quotaBytes")).longValue();
            s.db.update("UPDATE mailbox SET state=?,desired_state=?,quota_bytes=?,deleted_at=CASE WHEN ?='deleted' THEN now() ELSE NULL END,updated_at=now() WHERE id=?",state,state,quota,state,entity);
        }else if(kind.startsWith("alias.")){
            if(kind.equals("alias.delete"))s.db.update("DELETE FROM mailbox_alias WHERE id=?",entity);
            else s.db.update("UPDATE mailbox_alias SET state='active' WHERE id=?",entity);
        }else if(kind.equals("node.enable_management"))s.db.update("UPDATE mail_node SET readonly=false,inventory=?::jsonb,status='reachable',last_seen=now() WHERE id=?",s.encode(result),node);
        else if(kind.equals("diagnostics.read")){
            for(Object item:(List<?>)result.getOrDefault("checks",List.of()))recordCheck((UUID)node,s.map(item));
        }else if(kind.equals("backup.create"))s.db.update("UPDATE backup SET status='encrypted',summary=?::jsonb WHERE id=?",s.encode(result),entity);
        else if(kind.equals("backup.verify")){
            if(!Boolean.TRUE.equals(result.get("verified")))throw new IllegalStateException("Backup verification not confirmed");
            s.db.update("UPDATE backup SET status='verified',summary=?::jsonb WHERE id=?",s.encode(result),entity);
        }else if(kind.equals("backup.restore_drill"))s.db.update("UPDATE restore_drill SET state='verified_isolated_files',report=?::jsonb WHERE task_id=?",s.encode(result),task.get("id"));
    }
    private void recordCheck(UUID node,Map<String,Object> check){
        String name=String.valueOf(check.get("name")),state=String.valueOf(check.get("state"));
        if(name.length()>100||!Set.of("healthy","failed","degraded","unknown").contains(state))return;
        s.db.update("INSERT INTO monitor_check(node_id,name,state,detail,source,latency_ms) VALUES(?,?,?,?::jsonb,?,?)",node,name,state,s.encode(check),String.valueOf(check.getOrDefault("source","agent")),((Number)check.getOrDefault("latencyMs",0)).longValue());
        String key=node+":"+name;
        if(state.equals("failed")||state.equals("degraded"))s.db.update("INSERT INTO alert(id,dedupe_key,message) VALUES(?,?,?) ON CONFLICT(dedupe_key) DO UPDATE SET state='open',last_seen=now(),recovered_at=NULL",UUID.randomUUID(),key,"节点检查需要关注："+name);
        else if(state.equals("healthy"))s.db.update("UPDATE alert SET state='recovered',recovered_at=now(),last_seen=now() WHERE dedupe_key=? AND state='open'",key);
    }
    @Scheduled(fixedDelay=300000,initialDelay=30000)
    public void monitor(){
        for(var node:s.db.queryForList("SELECT id FROM mail_node LIMIT 100")){
            UUID id=(UUID)node.get("id");
            try{
                var health=agent.call(id,UUID.randomUUID().toString(),"health.read",Map.of());
                s.db.update("UPDATE mail_node SET status='reachable',inventory=?::jsonb,last_seen=now() WHERE id=?",s.encode(health),id);
                recordCheck(id,Map.of("name","agent.connection","state","healthy","source","agent"));
                var services=s.map(health.getOrDefault("services",Map.of()));
                services.forEach((name,state)->recordCheck(id,Map.of("name","service."+name,"state",state,"source","agent")));
                var probes=agent.call(id,UUID.randomUUID().toString(),"diagnostics.read",Map.of());
                for(Object check:(List<?>)probes.getOrDefault("checks",List.of()))recordCheck(id,s.map(check));
            }catch(Exception error){s.db.update("UPDATE mail_node SET status='offline' WHERE id=?",id);recordCheck(id,Map.of("name","agent.connection","state","failed","source","control_plane","code",error instanceof ApiError.Failure f?f.code:"PROBE_ERROR"));}
        }
    }
    @Scheduled(fixedDelay=60000,initialDelay=20000)
    public void housekeeping(){
        // A crashed worker is uncertain, not failed and not automatically restarted.
        var abandoned=s.db.queryForList("UPDATE task SET status='unknown',error_code='WORKER_INTERRUPTED',finished_at=now(),payload_cipher=NULL WHERE status='running' AND started_at<now()-interval '10 minutes' RETURNING id,entity_id,kind");
        for(var task:abandoned){
            String kind=task.get("kind").toString();
            if(kind.startsWith("mailbox."))s.db.update("UPDATE mailbox SET state='unknown' WHERE id=?",task.get("entity_id"));
            if(kind.equals("mail.send"))s.db.update("UPDATE mail_send SET state='unknown' WHERE id=?",task.get("id"));
            audit.add("worker","task.interrupted",task.get("id").toString(),"unknown",Map.of("method",kind));
        }
        s.db.update("UPDATE action_plan SET params_cipher='' WHERE expires_at<now() AND params_cipher<>''");
        s.db.update("DELETE FROM admin_session WHERE expires_at<now()");
        s.db.update("DELETE FROM rate_bucket WHERE window_start<now()-interval '2 days'");
        s.db.update("DELETE FROM monitor_check WHERE checked_at<now()-interval '30 days'");
    }
}
