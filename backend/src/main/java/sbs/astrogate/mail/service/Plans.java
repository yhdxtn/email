package sbs.astrogate.mail.service;

import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sbs.astrogate.mail.core.Crypto;
import sbs.astrogate.mail.security.Actor;
import sbs.astrogate.mail.security.AuthService;
import static sbs.astrogate.mail.api.ApiError.fail;

@Service
public class Plans {
    private final Store s;private final Crypto crypto;private final AuthService auth;private final Jobs jobs;private final Audit audit;
    public Plans(Store s,Crypto crypto,AuthService auth,Jobs jobs,Audit audit){this.s=s;this.crypto=crypto;this.auth=auth;this.jobs=jobs;this.audit=audit;}
    @Transactional
    public Map<String,Object> create(String kind,UUID node,UUID entity,Map<String,Object> params,Map<String,Object> preview,String confirmation){
        UUID id=UUID.randomUUID();Actor a=Actor.current();
        var storedPreview=new java.util.HashMap<>(preview);
        if(kind.equals("mail.send")){storedPreview.remove("body");storedPreview.remove("subject");}

        s.db.update("INSERT INTO action_plan(id,actor_id,kind,node_id,entity_id,params_cipher,preview,confirmation,fingerprint,expires_at) VALUES(?,?,?,?,?,?,?::jsonb,?,?,now()+interval '15 minutes')",id,a.id(),kind,node,entity,crypto.seal("plan:"+id,s.encode(params)),s.encode(storedPreview),confirmation,crypto.fingerprint(kind+"\n"+s.canonical(params)));
        audit.add(a.username(),"plan.preview",id.toString(),"ready",Map.of("method",kind));
        return Map.of("id",id,"kind",kind,"preview",preview,"confirmation",confirmation,"expiresInSeconds",900);
    }
    /** The caller checks a fixed per-kind role policy before invoking this method. */
    @Transactional
    public Map<String,Object> confirm(UUID id,String confirmation,String key){
        auth.requireFresh();Jobs.validateKey(key);Actor a=Actor.current();
        var row=s.one("SELECT * FROM action_plan WHERE id=? AND actor_id=? AND expires_at>now() FOR UPDATE",id,a.id());
        if(!Crypto.equal(row.get("confirmation").toString(),confirmation))throw fail(400,"CONFIRMATION_REQUIRED","确认文字不匹配");
        String kind=row.get("kind").toString();
        if(Boolean.TRUE.equals(row.get("used"))){if(key.equals(row.get("idempotency_key")))return s.one("SELECT id,status FROM task WHERE id=?",row.get("task_id"));throw fail(409,"PLAN_USED","计划已消费");}
        var params=s.map(crypto.open("plan:"+id,row.get("params_cipher").toString()));
        if(kind.equals("mail.send")){
            s.db.queryForObject("SELECT pg_advisory_xact_lock(7138159)",Object.class);
            long perDay=s.db.queryForObject("SELECT count(*) FROM mail_send WHERE actor_id=? AND created_at>now()-interval '24 hours'",Long.class,a.id());
            long recipient=s.db.queryForObject("SELECT count(*) FROM mail_send WHERE recipient=? AND created_at>now()-interval '1 hour'",Long.class,params.get("to"));
            if(perDay>=20||recipient>=3)throw fail(429,"SEND_RATE_LIMIT","测试发信限每管理员 20 封/滚动24小时、每目的地址 3 封/小时");
        }
        var task=jobs.submit(key,kind,(UUID)row.get("node_id"),(UUID)row.get("entity_id"),params);
        s.db.update("UPDATE action_plan SET used=true,task_id=?,idempotency_key=?,params_cipher='' WHERE id=?",task.get("id"),key,id);
        if(kind.equals("mail.send"))s.db.update("INSERT INTO mail_send(id,actor_id,sender,recipient) VALUES(?,?,?,?)",task.get("id"),a.id(),params.get("from"),params.get("to"));
        if(kind.equals("backup.restore_drill"))s.db.update("INSERT INTO restore_drill(id,backup_id,task_id) VALUES(?,?,?)",UUID.fromString(params.get("drillId").toString()),row.get("entity_id"),task.get("id"));
        return task;
    }
    public String kind(UUID id){return s.one("SELECT kind FROM action_plan WHERE id=? AND actor_id=?",id,Actor.current().id()).get("kind").toString();}
}
