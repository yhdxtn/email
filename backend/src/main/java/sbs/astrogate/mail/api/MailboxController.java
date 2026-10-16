package sbs.astrogate.mail.api;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import sbs.astrogate.mail.service.*;

@RestController
@RequestMapping("/api/v1")
@PreAuthorize("hasAnyRole('Owner','MailAdmin','DnsAdmin','Operator','Auditor')")
public class MailboxController {
    private final Store s;private final MailService mail;
    public MailboxController(Store s,MailService mail){this.s=s;this.mail=mail;}
    public record CreateMailbox(@NotNull UUID domainId,@NotBlank @Size(max=254) String address,@NotBlank @Size(max=256) String password,@Min(1048576) @Max(1099511627776L) long quotaBytes){}
    public record Mutation(@Size(max=256) String password,Long quotaBytes){}
    public record CreateAlias(@NotNull UUID domainId,@NotBlank String address,@NotBlank String destination){}
    @GetMapping("/mailboxes") public List<Map<String,Object>> list(@RequestParam(defaultValue="") String q,@RequestParam(defaultValue="0") int offset){
        if(q.length()>100||offset<0||offset>100000)throw new IllegalArgumentException("Query invalid");
        return s.db.queryForList("SELECT m.id,m.address,m.quota_bytes,m.used_bytes,m.state,m.last_login,m.last_failure,m.deleted_at,m.node_id,m.domain_id,m.created_at,n.name AS node_name FROM mailbox m JOIN mail_node n ON n.id=m.node_id WHERE m.address ILIKE ? ORDER BY m.created_at DESC LIMIT 100 OFFSET ?","%"+q+"%",offset);
    }
    @PostMapping("/mailboxes") @ResponseStatus(HttpStatus.ACCEPTED) public Map<String,Object> create(@Valid @RequestBody CreateMailbox body,@RequestHeader("Idempotency-Key") String key){return mail.createMailbox(body.domainId(),body.address(),body.password(),body.quotaBytes(),key);}
    @PostMapping("/mailboxes/{id}/{action:disable|enable|password-reset|quota}") @ResponseStatus(HttpStatus.ACCEPTED) public Map<String,Object> action(@PathVariable UUID id,@PathVariable String action,@RequestBody(required=false) Mutation body,@RequestHeader("Idempotency-Key") String key){return mail.action(id,action,body==null?null:body.password(),body==null?null:body.quotaBytes(),key);}
    @PostMapping("/mailboxes/{id}/delete-plan") public Map<String,Object> delete(@PathVariable UUID id){return mail.deletePlan(id);}
    @GetMapping("/aliases") public List<Map<String,Object>> aliases(){return s.db.queryForList("SELECT id,address,destination,state,node_id,created_at FROM mailbox_alias WHERE state<>'deleted' ORDER BY created_at DESC LIMIT 100");}
    @PostMapping("/aliases") @ResponseStatus(HttpStatus.ACCEPTED) public Map<String,Object> alias(@Valid @RequestBody CreateAlias body,@RequestHeader("Idempotency-Key") String key){return mail.createAlias(body.domainId(),body.address(),body.destination(),key);}
    @DeleteMapping("/aliases/{id}") @ResponseStatus(HttpStatus.ACCEPTED) public Map<String,Object> deleteAlias(@PathVariable UUID id,@RequestHeader("Idempotency-Key") String key){return mail.deleteAlias(id,key);}
}
