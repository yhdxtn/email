package sbs.astrogate.mail.service;

import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sbs.astrogate.mail.core.Crypto;
import sbs.astrogate.mail.security.Actor;
import static sbs.astrogate.mail.api.ApiError.fail;

@Service
public class Jobs {
    private final Store s;private final Crypto crypto;private final Audit audit;
    public Jobs(Store s,Crypto crypto,Audit audit){this.s=s;this.crypto=crypto;this.audit=audit;}
    public Map<String,Object> existing(String key,String kind,UUID node,Map<String,Object> params){
        validateKey(key);Actor a=Actor.current();String fingerprint=crypto.fingerprint(kind+"\n"+node+"\n"+s.canonical(params));
        var rows=s.db.queryForList("SELECT id,status,fingerprint FROM task WHERE actor_id=? AND idempotency_key=?",a.id(),key);
        if(rows.isEmpty())return null;var row=rows.getFirst();
        if(!Crypto.equal(fingerprint,row.get("fingerprint").toString()))throw fail(409,"IDEMPOTENCY_CONFLICT","同一幂等键不能用于不同请求");
        return Map.of("id",row.get("id"),"status",row.get("status"),"reused",true);
    }
    /** Must be called inside the same transaction as the entity's pending-state update. */
    @Transactional
    public Map<String,Object> submit(String key,String kind,UUID node,UUID entity,Map<String,Object> params){
        var old=existing(key,kind,node,params);if(old!=null)return old;Actor a=Actor.current();UUID id=UUID.randomUUID();
        s.db.update("INSERT INTO task(id,actor_id,kind,node_id,entity_id,idempotency_key,fingerprint,payload_cipher) VALUES(?,?,?,?,?,?,?,?)",id,a.id(),kind,node,entity,key,crypto.fingerprint(kind+"\n"+node+"\n"+s.canonical(params)),crypto.seal("task:"+id,s.encode(params)));
        audit.add(a.username(),"task.submit",entity==null?id.toString():entity.toString(),"queued",Map.of("method",kind,"taskId",id.toString()));
        return Map.of("id",id,"status","queued");
    }
    public static void validateKey(String key){if(key==null||!key.matches("[A-Za-z0-9_-]{16,100}"))throw fail(400,"IDEMPOTENCY_KEY_REQUIRED","需要长度 16–100 的 Idempotency-Key");}
    @Transactional
    public Map<String,Object> claim(){
        var rows=s.db.queryForList("SELECT * FROM task WHERE status='queued' ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED");
        if(rows.isEmpty())return null;var row=rows.getFirst();s.db.update("UPDATE task SET status='running',started_at=now(),attempts=attempts+1 WHERE id=?",row.get("id"));return row;
    }
    public Map<String,Object> payload(Map<String,Object> task){return s.map(crypto.open("task:"+task.get("id"),task.get("payload_cipher").toString()));}
    public void finish(UUID id,String status,Map<String,Object> result,String code){
        s.db.update("UPDATE task SET status=?,result=?::jsonb,error_code=?,finished_at=now(),payload_cipher=NULL WHERE id=?",status,s.encode(result),code,id);
    }
}
