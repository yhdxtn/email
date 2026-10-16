package sbs.astrogate.mail.core;

import java.util.*;

/** Pure planning logic. Only explicitly managed mail record slots may be changed. */
public final class DnsRules {
    private DnsRules() {}
    public record Record(String id,String type,String name,String content,int ttl,Integer priority,boolean proxied) {
        public String slot(){return type+":"+name+":"+(type.equals("TXT")?txtKind(content):"");}
        public String identity(){return slot()+":"+normalize(content)+":"+ttl+":"+priority+":"+proxied;}
        public Record withoutId(){return new Record(null,type,name,content,ttl,priority,proxied);}
    }
    public record Change(String action,Record before,Record after){}
    public static String normalize(String text){
        if(text==null)return "";String v=text.strip();
        if(v.startsWith("\"")&&v.endsWith("\""))v=v.substring(1,v.length()-1).replaceAll("\"\\s+\"","");
        return v;
    }
    private static String txtKind(String value){String text=normalize(value).toLowerCase(Locale.ROOT);if(text.startsWith("v=spf1"))return "spf";if(text.startsWith("v=dmarc1"))return "dmarc";if(text.startsWith("v=dkim1")||text.startsWith("p="))return "dkim";return "other";}
    public static List<Record> desired(String domain,String host,String ip,String selector,String dkim,String spf,String dmarc,int ttl){
        Checks.domain(domain);Checks.mailHost(host,domain);Checks.ipv4(ip);
        if(selector==null||!selector.matches("[a-z0-9][a-z0-9-]{0,62}"))throw new IllegalArgumentException("Invalid selector");
        if(ttl<60||ttl>86400)throw new IllegalArgumentException("Invalid TTL");
        Checks.text(spf,2048);Checks.text(dmarc,2048);
        if(!spf.startsWith("v=spf1 ")||!dmarc.startsWith("v=DMARC1;"))throw new IllegalArgumentException("Invalid authentication record");
        List<Record> records=new ArrayList<>();
        records.add(new Record(null,"A",host,ip,ttl,null,false));
        records.add(new Record(null,"MX",domain,host,ttl,10,false));
        records.add(new Record(null,"TXT",domain,spf,ttl,null,false));
        if(dkim!=null&&!dkim.isBlank()){
            Checks.text(dkim,8192);if(!dkim.startsWith("v=DKIM1;")||!dkim.matches(".*(?:^|[; ])p=[A-Za-z0-9+/=]+;? *$")||dkim.contains("PRIVATE"))throw new IllegalArgumentException("Expected a public DKIM TXT value");
            records.add(new Record(null,"TXT",selector+"._domainkey."+domain,dkim,ttl,null,false));
        }
        records.add(new Record(null,"TXT","_dmarc."+domain,dmarc,ttl,null,false));return List.copyOf(records);
    }
    public static List<Record> managed(List<Record> all,List<Record> desired,String domain){
        Set<String> slots=new HashSet<>();desired.forEach(r->slots.add(r.slot()));
        for(Record r:desired){
            if((r.type().equals("A")||r.type().equals("AAAA"))&&(r.name().equals(domain)||r.name().equals("www."+domain)))throw new IllegalArgumentException("Website address protected");
            if(!r.name().equals(domain)&&!r.name().endsWith("."+domain))throw new IllegalArgumentException("Out-of-zone record");
            if(!Set.of("A","MX","TXT").contains(r.type()))throw new IllegalArgumentException("Record type not managed");
        }
        for(Record existing:all)if(existing.type().equals("CNAME")&&desired.stream().anyMatch(d->d.name().equals(existing.name())))throw new IllegalArgumentException("CNAME conflict must be resolved manually");
        return all.stream().filter(r->slots.contains(r.slot())).toList();
    }
    public static List<Change> diff(List<Record> before,List<Record> desired,String domain){
        List<Record> old=new ArrayList<>(managed(before,desired,domain));List<Record> next=new ArrayList<>(desired);List<Change> changes=new ArrayList<>();
        // Identical records are left untouched, including provider IDs.
        var iterator=next.iterator();while(iterator.hasNext()){Record r=iterator.next();int i=-1;for(int j=0;j<old.size();j++)if(old.get(j).identity().equals(r.identity())){i=j;break;}if(i>=0){old.remove(i);iterator.remove();}}
        for(Record r:next){int i=-1;for(int j=0;j<old.size();j++)if(old.get(j).slot().equals(r.slot())){i=j;break;}if(i>=0)changes.add(new Change("update",old.remove(i),r));else changes.add(new Change("create",null,r));}
        for(Record r:old)changes.add(new Change("delete",r,null));return List.copyOf(changes);
    }
    public static String fingerprint(List<Record> records){return Crypto.sha256(String.join("\n",records.stream().map(Record::identity).sorted().toList()));}
}
