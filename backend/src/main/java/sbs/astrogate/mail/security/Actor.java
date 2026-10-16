package sbs.astrogate.mail.security;

import java.util.UUID;
import org.springframework.security.core.context.SecurityContextHolder;
import static sbs.astrogate.mail.api.ApiError.fail;

public record Actor(UUID id,String username,String role,UUID sessionId) {
    public static Actor current(){
        var authentication=SecurityContextHolder.getContext().getAuthentication();
        if(authentication==null || !(authentication.getPrincipal() instanceof Actor a))throw fail(401,"AUTH_REQUIRED","请先登录");
        return a;
    }
}
