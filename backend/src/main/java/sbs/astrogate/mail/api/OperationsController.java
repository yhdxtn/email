package sbs.astrogate.mail.api;

import java.util.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import sbs.astrogate.mail.security.*;
import sbs.astrogate.mail.service.*;
import static sbs.astrogate.mail.api.ApiError.fail;

@RestController
@RequestMapping("/api/v1")
public class OperationsController {
    private final Store s;private final Jobs jobs;private final Plans plans;private final AgentClient agent;private final Sender sender;private final Audit audit;
    public OperationsController(Store s,Jobs jobs,Plans plans,AgentClient agent,Sender sender,Audit audit){this.s=s;this.jobs=jobs;this.plans=plans;this.agent=agent;this.sender=sender;this.audit=audit;}
    public record Message(@NotBlank String from,@NotBlank String to,@NotBlank @Size(max=200) String subject,@NotBlank @Size(max=100000) String body,boolean html,List<Map<String,String>> attachments){}
    public record Observation(@NotBlank String state){}
    @PostMapping("/mail/test-send") @PreAuthorize("hasAnyRole('Owner','MailAdmin')") public Map<String,Object> preview(@Valid @RequestBody Message body){return sender.preview(body.from(),body.to(),body.subject(),body.body(),body.html(),body.attachments());}
    @GetMapping("/mail/sends") @PreAuthorize("hasAnyRole('Owner','MailAdmin','Auditor')") public List<Map<String,Object>> sends(){return s.db.queryForList("SELECT id,sender,recipient,message_id,state,recipient_confirmation,created_at FROM mail_send ORDER BY created_at DESC LIMIT 100");}
    @PostMapping("/mail/sends/{id}/observation") @PreAuthorize("hasAnyRole('Owner','MailAdmin')") public Map<String,Object> observation(@PathVariable UUID id,@Valid @RequestBody Observation body){if(!Set.of("unconfirmed","inbox_seen","spam_seen","reply_received").contains(body.state()))throw new IllegalArgumentException("Unknown observation");s.db.update("UPDATE mail_send SET recipient_confirmation=? WHERE id=?",body.state(),id);audit.add(Actor.current().username(),"mail.manual_observation",id.toString(),"recorded",Map.of("state",body.state(),"source","administrator_report"));return Map.of("state",body.state(),"source","administrator_report");}
    @GetMapping("/mail/queue") @PreAuthorize("hasAnyRole('Owner','MailAdmin','Operator','Auditor')") public Map<String,Object> queue(@RequestParam UUID nodeId){return agent.call(nodeId,UUID.randomUUID().toString(),"mail.queue.summary",Map.of());}
    @PostMapping("/mail/queue/{queueId}/retry") @PreAuthorize("hasAnyRole('Owner','MailAdmin')") @ResponseStatus(HttpStatus.ACCEPTED) public Map<String,Object> retry(@PathVariable String queueId,@RequestParam UUID nodeId,@RequestHeader("Idempotency-Key") String key){queueId(queueId);return jobs.submit(key,"mail.queue.retry_allowlisted",nodeId,null,Map.of("queueId",queueId));}
    @PostMapping("/mail/queue/{queueId}/delete-plan") @PreAuthorize("hasAnyRole('Owner','MailAdmin')") public Map<String,Object> deleteQueue(@PathVariable String queueId,@RequestParam UUID nodeId){queueId(queueId);var queue=queue(nodeId);var items=(List<?>)queue.get("items");var item=items.stream().map(s::map).filter(v->queueId.equals(v.get("queueId"))).findFirst().orElseThrow(()->fail(404,"QUEUE_ITEM_NOT_FOUND","队列项目不存在或不在当前列表范围"));return plans.create("mail.queue.delete_allowlisted",nodeId,null,Map.of("queueId",queueId),Map.of("item",item,"warning","删除待投递邮件不可撤销；不显示正文"),"DELETE QUEUE "+queueId);}
    private void queueId(String id){if(!id.matches("[A-Za-z0-9]{5,32}"))throw new IllegalArgumentException("Invalid queue ID");}
    @GetMapping("/backups") @PreAuthorize("hasAnyRole('Owner','Operator','Auditor')") public List<Map<String,Object>> backups(){return s.db.queryForList("SELECT id,node_id,task_id,archive_id,status,summary,created_at FROM backup ORDER BY created_at DESC LIMIT 100");}
    @PostMapping("/backups") @PreAuthorize("hasAnyRole('Owner','Operator')") @ResponseStatus(HttpStatus.ACCEPTED) @Transactional public Map<String,Object> backup(@RequestParam UUID nodeId,@RequestHeader("Idempotency-Key") String key){
        s.one("SELECT id FROM mail_node WHERE id=?",nodeId);Jobs.validateKey(key);
        // Deterministic archive ID makes retries of the same administrator/key a single backup.
        UUID id=UUID.nameUUIDFromBytes((Actor.current().id()+":"+nodeId+":"+key).getBytes(java.nio.charset.StandardCharsets.UTF_8));var params=Map.<String,Object>of("archiveId",id.toString());var old=jobs.existing(key,"backup.create",nodeId,params);if(old!=null)return old;
        var task=jobs.submit(key,"backup.create",nodeId,id,params);s.db.update("INSERT INTO backup(id,node_id,task_id,archive_id) VALUES(?,?,?,?)",id,nodeId,task.get("id"),id);return task;
    }
    @PostMapping("/backups/{id}/verify") @PreAuthorize("hasAnyRole('Owner','Operator')") @ResponseStatus(HttpStatus.ACCEPTED) public Map<String,Object> verify(@PathVariable UUID id,@RequestHeader("Idempotency-Key") String key){var backup=s.one("SELECT * FROM backup WHERE id=?",id);return jobs.submit(key,"backup.verify",(UUID)backup.get("node_id"),id,Map.of("archiveId",backup.get("archive_id").toString()));}
    @PostMapping("/backups/{id}/restore-drill") @PreAuthorize("hasRole('Owner')") public Map<String,Object> drill(@PathVariable UUID id){var backup=s.one("SELECT * FROM backup WHERE id=?",id);if(!backup.get("status").equals("verified"))throw fail(409,"VERIFY_BACKUP_FIRST","请先完整验证备份");UUID drill=UUID.randomUUID();return plans.create("backup.restore_drill",(UUID)backup.get("node_id"),id,Map.of("archiveId",backup.get("archive_id").toString(),"drillId",drill.toString()),Map.of("backupId",id,"destination","隔离目录 / 随机演练 ID","sourceUntouched",true,"scope","认证解密、文件校验及隔离提取；不是完整邮件服务灾备验收"),"RESTORE DRILL "+id);}
    @GetMapping("/restore-drills") @PreAuthorize("hasAnyRole('Owner','Operator','Auditor')") public List<Map<String,Object>> drills(){return s.db.queryForList("SELECT id,backup_id,state,report,created_at FROM restore_drill ORDER BY created_at DESC LIMIT 100");}
    @PostMapping("/nodes/{id}/import-mailboxes") @PreAuthorize("hasAnyRole('Owner','MailAdmin')") @Transactional public Map<String,Object> importMailboxes(@PathVariable UUID id){
        if(s.db.queryForObject("SELECT count(*) FROM task WHERE node_id=? AND status IN ('queued','running')",Integer.class,id)>0)throw fail(409,"NODE_HAS_PENDING_TASKS","先等待节点任务结束，再只读同步账户状态");
        var result=agent.call(id,UUID.randomUUID().toString(),"mailbox.list",Map.of());if(!Boolean.TRUE.equals(result.get("supported")))throw fail(409,"IMPORT_UNSUPPORTED","节点账户格式尚不支持；未猜测 mail-account 的命令参数");int count=0;
        for(Object item:(List<?>)result.get("items")){var r=s.map(item);String address=r.get("address").toString();sbs.astrogate.mail.core.Checks.email(address);var domains=s.db.queryForList("SELECT id FROM mail_domain WHERE name=? AND node_id=?",address.split("@")[1],id);if(domains.isEmpty())continue;
            String state=String.valueOf(r.get("state"));if(!Set.of("active","disabled","deleted").contains(state))continue;
            s.db.update("INSERT INTO mailbox(id,domain_id,node_id,address,quota_bytes,state,desired_state) VALUES(?,?,?,?,?,?,?) ON CONFLICT(address) DO UPDATE SET quota_bytes=EXCLUDED.quota_bytes,state=EXCLUDED.state,desired_state=EXCLUDED.desired_state,updated_at=now() WHERE mailbox.node_id=EXCLUDED.node_id",UUID.randomUUID(),domains.getFirst().get("id"),id,address,((Number)r.get("quotaBytes")).longValue(),state,state);count++;
        }audit.add(Actor.current().username(),"node.import_mailbox_metadata",id.toString(),"success",Map.of("count",count,"readonly",true));return Map.of("imported",count,"nodeModified",false,"hashesImported",false);
    }
}
