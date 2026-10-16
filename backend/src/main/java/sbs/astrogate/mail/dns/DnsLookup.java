package sbs.astrogate.mail.dns;

import java.util.*;
import javax.naming.directory.*;
import org.springframework.stereotype.Component;
import sbs.astrogate.mail.core.Checks;

@Component
public class DnsLookup {
    public Map<String,Object> query(String name,String type){
        if(!Set.of("A","AAAA","MX","TXT","NS","PTR","CNAME").contains(type)||name.length()>300||!name.matches("[a-zA-Z0-9_.-]+"))throw new IllegalArgumentException("Invalid DNS query");
        long start=System.nanoTime();List<String> values=new ArrayList<>();String state="healthy";
        var env=new Hashtable<String,String>();env.put("java.naming.factory.initial","com.sun.jndi.dns.DnsContextFactory");env.put("com.sun.jndi.dns.timeout.initial","2000");env.put("com.sun.jndi.dns.timeout.retries","1");
        DirContext context=null;
        try{context=new InitialDirContext(env);var attr=context.getAttributes(name,new String[]{type}).get(type);if(attr!=null){var all=attr.getAll();try{while(all.hasMore())values.add(all.next().toString());}finally{all.close();}}if(values.isEmpty())state="missing";}
        catch(javax.naming.NameNotFoundException e){state="missing";}catch(Exception e){state="unknown";}finally{if(context!=null)try{context.close();}catch(Exception ignored){}}
        // JNDI does not expose RR TTL or authoritative propagation: never invent either.
        return Map.of("name",name,"type",type,"values",values,"state",state,"latencyMs",(System.nanoTime()-start)/1000000,"source","system_recursive_resolver","ttlAvailable",false,"authoritativePropagation","not_measured");
    }
    @SuppressWarnings("unchecked") public List<String> authority(String domain){Checks.domain(domain);return (List<String>)query(domain,"NS").get("values");}
}
