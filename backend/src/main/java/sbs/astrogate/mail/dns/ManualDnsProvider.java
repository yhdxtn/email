package sbs.astrogate.mail.dns;

import java.util.List;
import sbs.astrogate.mail.core.DnsRules;
import static sbs.astrogate.mail.api.ApiError.fail;

public final class ManualDnsProvider implements DnsProvider {
    public String name(){return "manual";}
    public List<DnsRules.Record> listRecords(String zone,String token){throw fail(409,"MANUAL_DNS","手动模式使用公开 DNS 检测，不假装拥有整个 Zone 清单");}
    public void applyChanges(String zone,String token,List<DnsRules.Change> changes){throw fail(409,"MANUAL_DNS","请在实际权威 DNS 托管商后台手工修改");}
}
