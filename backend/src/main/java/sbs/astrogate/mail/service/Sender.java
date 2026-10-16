package sbs.astrogate.mail.service;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.UUID;
import jakarta.activation.DataHandler;
import jakarta.mail.*;
import jakarta.mail.internet.*;
import jakarta.mail.util.ByteArrayDataSource;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import sbs.astrogate.mail.core.*;
import sbs.astrogate.mail.security.Actor;
import sbs.astrogate.mail.security.RateLimiter;
import static sbs.astrogate.mail.api.ApiError.fail;

@Service
public class Sender {
    private final Store s;private final Plans plans;private final RateLimiter rate;
    public Sender(Store s,Plans plans,RateLimiter rate){this.s=s;this.plans=plans;this.rate=rate;}
    @PreAuthorize("hasAnyRole('Owner','MailAdmin')")
    public Map<String,Object> preview(String from,String to,String subject,String body,boolean html,List<Map<String,String>> attachments){
        rate.check("mail-preview:"+Actor.current().id(),20,600);
        Checks.email(from);Checks.email(to);Checks.text(subject,200);
        if(!Config.set("TEST_RECIPIENTS").contains(to))throw fail(403,"RECIPIENT_NOT_AUTHORIZED","收件人不在部署级 TEST_RECIPIENTS 允许清单中");
        Set<String> allowed=Config.set("SMTP_ALLOWED_FROM");if(allowed.isEmpty())allowed=Set.of(Config.env("SMTP_USERNAME",""));
        if(!allowed.contains(from)||s.db.queryForObject("SELECT count(*) FROM mail_domain WHERE name=?",Long.class,from.substring(from.indexOf('@')+1))==0)throw fail(403,"SENDER_NOT_AUTHORIZED","发件地址或域名未获授权");
        if(Config.env("SMTP_HOST","").isBlank()||Config.secret("SMTP_PASSWORD").isBlank())throw fail(409,"SMTP_UNCONFIGURED","SMTP 服务端连接尚未配置");
        if(body==null||body.isBlank()||body.length()>100000)throw new IllegalArgumentException("Invalid message body");
        String clean=html?Jsoup.clean(body,new Safelist().addTags("p","br","b","i","strong","em","ul","ol","li","code","pre","blockquote")):body;
        List<Map<String,Object>> safeAttachments=new ArrayList<>(),overview=new ArrayList<>();int total=0;
        if(attachments!=null){
            if(attachments.size()>2)throw fail(400,"ATTACHMENT_LIMIT","最多 2 个附件");
            for(var item:attachments){
                if(!item.keySet().equals(Set.of("name","base64")))throw new IllegalArgumentException("Unknown attachment field");
                String name=item.get("name");if(name==null||name.startsWith(".")||!name.matches("[A-Za-z0-9_ .\\p{IsHan}-]{1,80}\\.(txt|pdf|png|jpg|jpeg)"))throw fail(400,"ATTACHMENT_TYPE","仅允许 txt/pdf/png/jpg，文件名不能含路径");
                String encoded=item.get("base64");if(encoded==null||encoded.length()>1400000)throw fail(400,"ATTACHMENT_LIMIT","每个附件最多 1 MiB");
                byte[] data=Base64.getDecoder().decode(encoded);total+=data.length;if(data.length>1048576||total>2097152)throw fail(400,"ATTACHMENT_LIMIT","附件总大小最多 2 MiB");
                String ext=name.substring(name.lastIndexOf('.')+1);String type=switch(ext){case "pdf"->"application/pdf";case "png"->"image/png";case "jpg","jpeg"->"image/jpeg";default->"text/plain";};
                if(ext.equals("pdf")&&(data.length<5||!new String(Arrays.copyOf(data,5),StandardCharsets.US_ASCII).equals("%PDF-")))throw fail(400,"ATTACHMENT_SIGNATURE","附件内容与类型不符");
                if(ext.equals("png")&&(data.length<8||!Arrays.equals(Arrays.copyOf(data,8),new byte[]{(byte)137,80,78,71,13,10,26,10})))throw fail(400,"ATTACHMENT_SIGNATURE","附件内容与类型不符");
                if((ext.equals("jpg")||ext.equals("jpeg"))&&(data.length<3||data[0]!=(byte)255||data[1]!=(byte)216||data[2]!=(byte)255))throw fail(400,"ATTACHMENT_SIGNATURE","附件内容与类型不符");
                safeAttachments.add(Map.of("name",name,"base64",encoded,"type",type));overview.add(Map.of("name",name,"size",data.length));
            }
        }
        var params=Map.<String,Object>of("from",from,"to",to,"subject",subject,"body",clean,"html",html,"attachments",safeAttachments);
        return plans.create("mail.send",null,null,params,Map.of("from",from,"to",to,"subject",subject,"body",clean,"html",html,"attachments",overview,"deliveryWarning","SMTP 接受不等于进入收件箱；本系统不读取收件人邮箱"),"SEND "+to);
    }
    /** Called only by the durable worker. No SMTP endpoint or credentials may originate in payload. */
    public Map<String,Object> send(UUID taskId,Map<String,Object> p){
        String host=Config.env("SMTP_HOST","");String username=Config.env("SMTP_USERNAME","");String password=Config.secret("SMTP_PASSWORD");
        if(host.isBlank()||username.isBlank()||password.isBlank())throw fail(409,"SMTP_UNCONFIGURED","SMTP 尚未配置");
        if(!Config.set("TEST_RECIPIENTS").contains(p.get("to")))throw fail(403,"RECIPIENT_NOT_AUTHORIZED","收件人授权已撤销");
        Set<String> senders=Config.set("SMTP_ALLOWED_FROM");if(senders.isEmpty())senders=Set.of(username);
        if(!senders.contains(p.get("from")))throw fail(403,"SENDER_NOT_AUTHORIZED","发件人授权已撤销");
        Properties props=new Properties();props.setProperty("mail.smtp.auth","true");props.setProperty("mail.smtp.starttls.enable","true");props.setProperty("mail.smtp.starttls.required","true");props.setProperty("mail.smtp.ssl.checkserveridentity","true");props.setProperty("mail.smtp.connectiontimeout","5000");props.setProperty("mail.smtp.timeout","10000");props.setProperty("mail.smtp.writetimeout","10000");props.setProperty("mail.smtp.ssl.protocols","TLSv1.2 TLSv1.3");props.setProperty("mail.debug","false");
        String messageId="<"+taskId+"@"+p.get("from").toString().split("@")[1]+">";boolean dataAttempted=false;
        s.db.update("UPDATE mail_send SET state='connecting',message_id=? WHERE id=?",messageId,taskId);
        try{
            Session session=Session.getInstance(props);session.setDebug(false);MimeMessage message=new MimeMessage(session);
            message.setFrom(new InternetAddress(p.get("from").toString(),true));message.setRecipient(Message.RecipientType.TO,new InternetAddress(p.get("to").toString(),true));message.setSubject(p.get("subject").toString(),"UTF-8");message.setSentDate(new Date());
            MimeMultipart multipart=new MimeMultipart("mixed");MimeBodyPart text=new MimeBodyPart();text.setContent(p.get("body").toString(),Boolean.TRUE.equals(p.get("html"))?"text/html; charset=UTF-8":"text/plain; charset=UTF-8");multipart.addBodyPart(text);
            for(Object item:(List<?>)p.get("attachments")){var attachment=s.map(item);MimeBodyPart part=new MimeBodyPart();part.setDataHandler(new DataHandler(new ByteArrayDataSource(Base64.getDecoder().decode(attachment.get("base64").toString()),attachment.get("type").toString())));part.setFileName(MimeUtility.encodeText(attachment.get("name").toString(),"UTF-8",null));part.setDisposition(Part.ATTACHMENT);multipart.addBodyPart(part);}
            message.setContent(multipart);message.saveChanges();message.setHeader("Message-ID",messageId);
            Transport transport=session.getTransport("smtp");
            try{transport.connect(host,587,username,password);dataAttempted=true;transport.sendMessage(message,message.getAllRecipients());}
            finally{try{transport.close();}catch(MessagingException ignored){}}
            s.db.update("UPDATE mail_send SET state='smtp_accepted' WHERE id=?",taskId);
            return Map.of("messageId",messageId,"state","smtp_accepted","remoteMxAccepted","unknown","inboxDelivery","unconfirmed","automaticRetry",false);
        }catch(AuthenticationFailedException e){throw fail(502,"SMTP_AUTH_FAILED","SMTP 身份验证失败");}
        catch(Exception e){
            Throwable cursor=e;boolean tls=false;for(int i=0;cursor!=null&&i<12;i++,cursor=cursor.getCause())if(cursor instanceof javax.net.ssl.SSLException)tls=true;
            if(tls)throw fail(502,"SMTP_TLS_ERROR","SMTP TLS 证书或协议验证失败");
            throw fail(502,dataAttempted?"SMTP_RESULT_UNKNOWN":"SMTP_CONNECTION_FAILED",dataAttempted?"提交阶段中断，投递结果未知；不自动重发":"SMTP 连接未成功");
        }
    }
}
