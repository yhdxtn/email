import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import sbs.astrogate.mail.core.*;
import sbs.astrogate.mail.core.DnsRules.Record;

/** Dependency-free executable tests. This does NOT stand in for Spring/PostgreSQL integration tests. */
public class CoreChecks {
    static int checks=0;
    static void check(boolean ok,String name){checks++;if(!ok)throw new AssertionError(name);}
    static void rejects(Runnable fn,String name){checks++;try{fn.run();}catch(IllegalArgumentException expected){return;}throw new AssertionError("Accepted invalid input: "+name);}
    public static void main(String[] args){
        check(Checks.domain("example.test").equals("example.test"),"domain");
        for(String invalid:List.of("EXAMPLE.test","example..test","-a.example.test","example.test.","a.test;reboot","http://example.test","a.test/../etc","example.test\n"))rejects(()->Checks.domain(invalid),"domain "+invalid);
        for(String invalid:List.of("a@example.test,b@example.test","../a@example.test","a..b@example.test","a@example.test\r\nBcc:x@example.test","a@localhost","a@a@example.test"))rejects(()->Checks.email(invalid),"address");
        check(Checks.email("a+b@example.test").equals("a+b@example.test"),"plus addressing");
        for(String invalid:List.of("256.1.1.1","01.2.3.4","1.2.3","127.1","1.2.3.4 "))rejects(()->Checks.ipv4(invalid),"ip");
        rejects(()->Checks.mailHost("www.example.test","example.test"),"website");
        rejects(()->Checks.mailHost("example.test","example.test"),"apex");
        rejects(()->Checks.mailHost("mail.evil.test","example.test"),"out of zone");
        rejects(()->Checks.password("short"),"short password");
        rejects(()->Checks.password("汉".repeat(25)),"bcrypt byte boundary");
        rejects(()->Checks.password("longPassword\ninvalid"),"control");
        rejects(()->Checks.quota(1),"small quota");rejects(()->Checks.quota(1099511627777L),"large quota");
        check(Checks.quota(1048576)==1048576,"minimum quota");
        byte[] key=Crypto.random(32);Crypto crypto=new Crypto(key);
        String secret="runtime-generated-test-value "+Crypto.token(),encrypted=crypto.seal("task:1",secret);
        check(crypto.open("task:1",encrypted).equals(secret),"AES round trip");
        check(!encrypted.contains(secret),"ciphertext not plaintext");
        check(!crypto.seal("task:1",secret).equals(encrypted),"random IV");
        rejects(()->crypto.open("task:2",encrypted),"AAD purpose binding");
        rejects(()->new Crypto(Crypto.random(32)).open("task:1",encrypted),"wrong key");
        byte[] raw=Base64.getDecoder().decode(encrypted.substring(6));raw[raw.length-1]^=1;
        rejects(()->crypto.open("task:1","v1:k1:"+Base64.getEncoder().encodeToString(raw)),"GCM integrity");
        rejects(()->crypto.open("task:1","v0:k1:abc"),"envelope version");
        check(Crypto.equal("x","x")&&!Crypto.equal("x","y")&&!Crypto.equal(null,null),"constant comparison semantics");
        check(Crypto.token().matches("[A-Za-z0-9_-]{43}"),"token strength format");
        check(Crypto.sha256("abc").equals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),"SHA256 vector");
        String totp=Totp.encode("12345678901234567890".getBytes(StandardCharsets.US_ASCII));
        long[] times={59,1111111109,1111111111,1234567890,2000000000,20000000000L};
        String[] codes={"287082","081804","050471","005924","279037","353130"};
        for(int i=0;i<times.length;i++)check(Totp.code(totp,times[i]/30).equals(codes[i]),"RFC6238 truncated 6 digit vector "+i);
        long now=1234567890;String otp=Totp.code(totp,now/30);
        check(Totp.verify(totp,otp,Instant.ofEpochSecond(now),-1)==now/30,"TOTP accept");
        check(Totp.verify(totp,otp,Instant.ofEpochSecond(now),now/30)==-1,"TOTP replay");
        check(Totp.verify(totp,otp,Instant.ofEpochSecond(now+90),-1)==-1,"TOTP expiry");
        check(Totp.verify(totp,"12345",Instant.ofEpochSecond(now),-1)==-1,"TOTP length");
        check(Arrays.equals(Totp.decode(totp),"12345678901234567890".getBytes(StandardCharsets.US_ASCII)),"Base32 roundtrip");
        var desired=DnsRules.desired("example.test","mail.example.test","192.0.2.10","mail","v=DKIM1; k=rsa; p=YWJjZA==","v=spf1 mx -all","v=DMARC1; p=none;",300);
        check(desired.size()==5,"five DNS records");
        var website=new Record("website","A","example.test","192.0.2.20",300,null,false);
        var www=new Record("www","A","www.example.test","192.0.2.20",300,null,false);
        var unrelated=new Record("verify","TXT","example.test","google-site-verification=fictitious",300,null,false);
        List<Record> all=new ArrayList<>(desired);all.addAll(List.of(website,www,unrelated));
        check(DnsRules.diff(all,desired,"example.test").isEmpty(),"ignore website/verification records");
        check(DnsRules.managed(all,desired,"example.test").size()==5,"managed record count");
        var oldMail=new Record("oldmail","A","mail.example.test","192.0.2.55",300,null,false);
        var edits=DnsRules.diff(List.of(website,www,oldMail,unrelated),desired,"example.test");
        check(edits.size()==5,"diff minimal");
        check(edits.stream().noneMatch(e->e.before()!=null&&Set.of("website","www","verify").contains(e.before().id())),"website protected in diff");
        var collision=new Record("alias","CNAME","mail.example.test","elsewhere.test",300,null,false);
        rejects(()->DnsRules.diff(List.of(collision),desired,"example.test"),"CNAME conflict");
        rejects(()->DnsRules.managed(List.of(),List.of(website),"example.test"),"apex A injection");
        rejects(()->DnsRules.desired("example.test","mail.example.test","192.0.2.10","mail","PRIVATE KEY","v=spf1 mx -all","v=DMARC1; p=none;",300),"private DKIM");
        var reverse=new ArrayList<>(all);Collections.reverse(reverse);
        check(DnsRules.fingerprint(all).equals(DnsRules.fingerprint(reverse)),"order-independent snapshot");
        check(DnsRules.normalize("\"v=spf1 \" \"mx -all\"").equals("v=spf1 mx -all"),"split TXT chunks");
        System.out.println("PASS: "+checks+" Java core assertions (no Spring/DB/SMTP integration claimed)");
    }
}
