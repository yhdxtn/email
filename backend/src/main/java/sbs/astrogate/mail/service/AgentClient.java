package sbs.astrogate.mail.service;

import java.io.InputStream;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import javax.net.ssl.*;
import org.springframework.stereotype.Service;
import sbs.astrogate.mail.core.Config;
import sbs.astrogate.mail.core.Crypto;
import static sbs.astrogate.mail.api.ApiError.fail;

@Service
public class AgentClient {
    private final Store s;
    public AgentClient(Store s){this.s=s;}
    public boolean configured(){return !Config.env("AGENT_URL","").isBlank();}
    public Map<String,Object> call(UUID node,String id,String method,Map<String,Object> params){
        var row=s.one("SELECT instance_id,connection_ref FROM mail_node WHERE id=?",node);
        if(!row.get("connection_ref").equals("primary"))throw fail(409,"NODE_UNSUPPORTED","该节点没有部署级连接绑定");
        String instance=row.get("instance_id").toString();
        if(!instance.equals(Config.env("AGENT_INSTANCE_ID","")))throw fail(409,"INSTANCE_MISMATCH","Agent 实例身份与部署绑定不一致");
        if(!configured())throw fail(503,"AGENT_UNCONFIGURED","尚未配置 Agent 连接");
        try{
            URI base=URI.create(Config.env("AGENT_URL",""));
            if(base.getUserInfo()!=null||base.getQuery()!=null||base.getFragment()!=null||(!"https".equals(base.getScheme())&&!(Config.local()&&"http".equals(base.getScheme())&&java.util.Set.of("127.0.0.1","localhost").contains(base.getHost()))))throw new IllegalArgumentException("Invalid agent endpoint");
            var builder=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(4)).followRedirects(HttpClient.Redirect.NEVER);
            if(base.getScheme().equals("https"))builder.sslContext(context());
            HttpClient client=builder.build();
            byte[] secret=Base64.getDecoder().decode(Config.secret("AGENT_SIGNING_KEY"));if(secret.length!=32)throw new IllegalArgumentException("Invalid signing key");
            String nonce=Crypto.token();String timestamp=Long.toString(Instant.now().getEpochSecond());
            byte[] body=s.encode(Map.of("version",1,"jobId",id,"method",method,"params",params)).getBytes(StandardCharsets.UTF_8);
            byte[] prefix=(timestamp+"\n"+nonce+"\n"+instance+"\n").getBytes(StandardCharsets.UTF_8);
            byte[] signed=new byte[prefix.length+body.length];System.arraycopy(prefix,0,signed,0,prefix.length);System.arraycopy(body,0,signed,prefix.length,body.length);
            var request=HttpRequest.newBuilder(base.resolve("/rpc/v1")).timeout(Duration.ofSeconds(method.startsWith("backup.")?120:25))
                .header("Content-Type","application/json").header("X-Instance-ID",instance).header("X-Timestamp",timestamp)
                .header("X-Nonce",nonce).header("X-Signature",Crypto.hmac(secret,signed)).POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
            var response=client.send(request,HttpResponse.BodyHandlers.ofInputStream());
            try(InputStream in=response.body()){
                byte[] bytes=in.readNBytes(1024*1024+1);if(bytes.length>1024*1024)throw fail(502,"AGENT_RESPONSE_TOO_LARGE","Agent 响应超过限制");
                var result=s.map(new String(bytes,StandardCharsets.UTF_8));
                if(response.statusCode()!=200){String code=String.valueOf(result.getOrDefault("code","AGENT_REJECTED"));if(!code.matches("[A-Z0-9_]{1,80}"))code="AGENT_REJECTED";throw fail(502,code,"Agent 拒绝操作；请查看兼容性、只读状态和任务记录");}
                return result;
            }
        }catch(sbs.astrogate.mail.api.ApiError.Failure e){throw e;}
        catch(javax.net.ssl.SSLException e){throw fail(503,"AGENT_TLS_ERROR","Agent TLS 验证失败");}
        catch(Exception e){if(e instanceof InterruptedException)Thread.currentThread().interrupt();throw fail(503,"AGENT_OFFLINE_OR_TIMEOUT","Agent 离线或超时；节点状态尚未确认");}
    }
    private SSLContext context()throws Exception{
        char[] pass=Config.secret("AGENT_KEYSTORE_PASSWORD").toCharArray();
        KeyStore keys=KeyStore.getInstance("PKCS12");try(var in=Files.newInputStream(Path.of(Config.env("AGENT_CLIENT_KEYSTORE","/run/secrets/agent-client.p12")))){keys.load(in,pass);}
        KeyStore trust=KeyStore.getInstance("PKCS12");try(var in=Files.newInputStream(Path.of(Config.env("AGENT_TRUSTSTORE","/run/secrets/agent-trust.p12")))){trust.load(in,pass);}
        KeyManagerFactory km=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());km.init(keys,pass);
        TrustManagerFactory tm=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());tm.init(trust);
        SSLContext context=SSLContext.getInstance("TLS");context.init(km.getKeyManagers(),tm.getTrustManagers(),null);return context;
    }
}
