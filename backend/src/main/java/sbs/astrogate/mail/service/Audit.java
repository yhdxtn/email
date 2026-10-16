package sbs.astrogate.mail.service;

import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Service
public class Audit {
    private final Store s;
    public Audit(Store s){this.s=s;}
    private static final Set<String> SAFE_KEYS=Set.of("state","role","quotaBytes","provider","count","method","errorCode","taskId","planId","messageId","readonly","confirmation","source");
    public void add(String actor,String action,String target,String outcome,Map<String,?> details){
        if(!SAFE_KEYS.containsAll(details.keySet())) throw new IllegalArgumentException("Unsafe audit field");
        UUID requestId=UUID.randomUUID();
        if(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs){Object id=attrs.getRequest().getAttribute("requestId");if(id!=null)requestId=UUID.fromString(id.toString());}
        s.db.update("INSERT INTO audit_event(actor,action,target,outcome,request_id,summary) VALUES(?,?,?,?,?,?::jsonb)",actor,action,target,outcome,requestId,s.encode(details));
    }
}
