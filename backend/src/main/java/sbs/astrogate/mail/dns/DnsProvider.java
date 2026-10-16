package sbs.astrogate.mail.dns;

import java.util.List;
import sbs.astrogate.mail.core.DnsRules;

public interface DnsProvider {
    String name();
    List<DnsRules.Record> listRecords(String zone,String token);
    void applyChanges(String zone,String token,List<DnsRules.Change> changes);
}
