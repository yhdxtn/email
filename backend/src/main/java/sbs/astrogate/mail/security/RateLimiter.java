package sbs.astrogate.mail.security;

import java.sql.Timestamp;
import java.time.Instant;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import sbs.astrogate.mail.service.Store;
import static sbs.astrogate.mail.api.ApiError.fail;

@Service
public class RateLimiter {
    private final Store s; private final org.springframework.transaction.support.TransactionTemplate tx;
    public RateLimiter(Store s, org.springframework.transaction.PlatformTransactionManager manager){this.s=s;this.tx=new org.springframework.transaction.support.TransactionTemplate(manager);this.tx.setPropagationBehavior(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);}
    /** Commits independently so failed authentication cannot roll back attempt counts. */
    @Transactional(propagation=Propagation.REQUIRES_NEW)
    public int consume(String bucket,int windowSeconds){
        return tx.execute(status -> s.db.queryForObject("INSERT INTO rate_bucket(bucket,window_start,attempts) VALUES(?,now(),1) ON CONFLICT(bucket) DO UPDATE SET attempts=CASE WHEN rate_bucket.window_start < now()-(? * interval '1 second') THEN 1 ELSE rate_bucket.attempts+1 END,window_start=CASE WHEN rate_bucket.window_start < now()-(? * interval '1 second') THEN now() ELSE rate_bucket.window_start END RETURNING attempts",Integer.class,bucket,windowSeconds,windowSeconds));
    }
    public void check(String bucket,int limit,int windowSeconds){if(consume(bucket,windowSeconds)>limit)throw fail(429,"RATE_LIMITED","操作过于频繁，请稍后重试");}
}
