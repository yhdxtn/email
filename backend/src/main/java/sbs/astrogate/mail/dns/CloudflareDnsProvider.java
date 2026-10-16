package sbs.astrogate.mail.dns;

import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import org.springframework.stereotype.Component;
import sbs.astrogate.mail.core.Checks;
import sbs.astrogate.mail.core.DnsRules;
import sbs.astrogate.mail.service.Store;
import static sbs.astrogate.mail.api.ApiError.fail;

@Component
public class CloudflareDnsProvider implements DnsProvider {
    private static final String BASE="https://api.cloudflare.com/client/v4/zones/";
    private final Store s;private final HttpClient client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build();
    public CloudflareDnsProvider(Store s){this.s=s;}
    public String name(){return "cloudflare";}
    public List<DnsRules.Record> listRecords(String zone,String token){
        Checks.zone(zone);List<DnsRules.Record> all=new ArrayList<>();
        for(int page=1;page<=20;page++){
            var response=request("GET",zone+"/dns_records?per_page=500&page="+page,token,null);
            var result=(List<?>)response.get("result");
            for(Object item:result){var r=s.map(item);String type=r.get("type").toString();if(!Set.of("A","AAAA","MX","TXT","CNAME").contains(type))continue;
                all.add(new DnsRules.Record(r.get("id").toString(),type,r.get("name").toString(),r.get("content").toString(),((Number)r.get("ttl")).intValue(),r.get("priority")==null?null:((Number)r.get("priority")).intValue(),Boolean.TRUE.equals(r.get("proxied"))));}
            var info=s.map(response.get("result_info"));if(page>=((Number)info.get("total_pages")).intValue())return List.copyOf(all);
        }throw fail(409,"ZONE_TOO_LARGE","Zone 超过安全分页上限，请手工管理");
    }
    public Map<String,Object> zoneInfo(String zone,String token){return s.map(request("GET",Checks.zone(zone),token,null).get("result"));}
    public void applyChanges(String zone,String token,List<DnsRules.Change> changes){
        Checks.zone(zone);if(changes.size()>100)throw fail(400,"TOO_MANY_DNS_CHANGES","单次最多 100 项 DNS 变更");
        if(changes.isEmpty())return;List<Map<String,Object>> deletes=new ArrayList<>(),puts=new ArrayList<>(),posts=new ArrayList<>();
        for(var change:changes){switch(change.action()){
            case "delete"->deletes.add(Map.of("id",recordId(change.before().id())));
            case "update"->{var body=recordBody(change.after());body.put("id",recordId(change.before().id()));puts.add(body);}
            case "create"->posts.add(recordBody(change.after()));default->throw new IllegalArgumentException("Unsupported DNS action");}}
        request("POST",zone+"/dns_records/batch",token,Map.of("deletes",deletes,"puts",puts,"posts",posts));
    }
    private String recordId(String id){return Checks.zone(id);}
    private Map<String,Object> recordBody(DnsRules.Record r){var body=new HashMap<String,Object>();body.put("type",r.type());body.put("name",r.name());body.put("content",r.content());body.put("ttl",r.ttl());if(r.priority()!=null)body.put("priority",r.priority());if(r.type().equals("A")||r.type().equals("AAAA"))body.put("proxied",false);return body;}
    private Map<String,Object> request(String method,String suffix,String token,Object payload){
        if(token==null||!token.matches("[A-Za-z0-9_-]{20,256}"))throw fail(409,"DNS_TOKEN_MISSING","请配置最小权限 API Token");
        try{
            var builder=HttpRequest.newBuilder(URI.create(BASE+suffix)).timeout(Duration.ofSeconds(15)).header("Authorization","Bearer "+token).header("Content-Type","application/json");
            if(method.equals("GET"))builder.GET();else builder.POST(HttpRequest.BodyPublishers.ofString(s.encode(payload)));
            var response=client.send(builder.build(),HttpResponse.BodyHandlers.ofInputStream());
            try(var in=response.body()){
                byte[] bytes=in.readNBytes(2*1024*1024+1);if(bytes.length>2*1024*1024)throw fail(502,"DNS_RESPONSE_TOO_LARGE","DNS API 响应超过限制");
                if(response.statusCode()==401||response.statusCode()==403)throw fail(403,"DNS_PERMISSION_DENIED","DNS Token 无权访问该区域，请手工修改或修正授权");
                if(response.statusCode()<200||response.statusCode()>299)throw fail(502,"DNS_PROVIDER_ERROR","DNS provider 请求失败；未回退到网页自动化");
                var body=s.map(new String(bytes,StandardCharsets.UTF_8));if(!Boolean.TRUE.equals(body.get("success")))throw fail(502,"DNS_PROVIDER_REJECTED","DNS provider 拒绝操作");return body;
            }
        }catch(sbs.astrogate.mail.api.ApiError.Failure e){throw e;}catch(Exception e){if(e instanceof InterruptedException)Thread.currentThread().interrupt();throw fail(502,"DNS_PROVIDER_TIMEOUT","DNS API 无响应或网络验证失败；写操作需检查实际状态");}
    }
}
