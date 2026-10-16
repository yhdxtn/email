package sbs.astrogate.mail;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import sbs.astrogate.mail.core.*;
import sbs.astrogate.mail.service.Jobs;
import sbs.astrogate.mail.service.Store;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Requires Docker, Maven dependencies, and the ephemeral env created by scripts/test_all.py. */
@SpringBootTest(properties={"app.jobs.enabled=false","admin.trusted-proxy-cidrs=10.20.0.0/24"})
@AutoConfigureMockMvc
@Testcontainers
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ControlPlaneIntegrationTest {
    @Container static final PostgreSQLContainer<?> postgres=new PostgreSQLContainer<>("postgres:17.11-bookworm");
    @DynamicPropertySource static void database(DynamicPropertyRegistry registry){registry.add("spring.datasource.url",postgres::getJdbcUrl);registry.add("spring.datasource.username",postgres::getUsername);registry.add("spring.datasource.password",postgres::getPassword);registry.add("spring.flyway.user",postgres::getUsername);registry.add("spring.flyway.password",postgres::getPassword);}
    @Autowired MockMvc mvc;@Autowired ObjectMapper json;@Autowired JdbcTemplate db;@Autowired Crypto crypto;@Autowired PasswordEncoder encoder;
    static Cookie ownerCookie;static String ownerPassword;
    @Test @Order(1) void newDatabaseAndSingleUseSetup()throws Exception{
        ownerPassword=Crypto.token();
        mvc.perform(get("/api/v1/overview")).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/setup/initialize").contentType("application/json").content("{}")).andExpect(status().isForbidden());
        mvc.perform(get("/api/v1/setup/status")).andExpect(jsonPath("$.needsSetup").value(true));
        var body=json.writeValueAsString(Map.of("username","test-owner","password",ownerPassword,"token",Config.secret("APP_SETUP_TOKEN")));
        mvc.perform(post("/api/v1/setup/initialize").with(csrf()).contentType("application/json").content(body)).andExpect(status().isOk());
        mvc.perform(post("/api/v1/setup/initialize").with(csrf()).contentType("application/json").content(body)).andExpect(status().isConflict());
        assertEquals(1,db.queryForObject("SELECT count(*) FROM admin_user",Integer.class));
    }
    @Test @Order(2) void passwordLoginOpensConsoleAndPasswordReauthProtectsSensitiveActions()throws Exception{
        var result=mvc.perform(post("/api/v1/auth/login").with(csrf()).contentType("application/json").content(json.writeValueAsString(Map.of("username","test-owner","password",ownerPassword))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.authenticated").value(true)).andReturn();
        String set=result.getResponse().getHeader("Set-Cookie");assertNotNull(set);assertTrue(set.contains("Max-Age=28800"));String token=set.split(";",2)[0].split("=",2)[1];ownerCookie=new Cookie("AGSESSION",token);
        mvc.perform(get("/api/v1/auth/me").cookie(ownerCookie)).andExpect(status().isOk()).andExpect(jsonPath("$.username").value("test-owner"));
        mvc.perform(get("/api/v1/overview").cookie(ownerCookie)).andExpect(status().isOk()).andExpect(jsonPath("$.releaseGate").value("NOT_PRODUCTION_ACCEPTED"));
        mvc.perform(post("/api/v1/auth/reauth").cookie(ownerCookie).with(csrf()).contentType("application/json").content(json.writeValueAsString(Map.of("password","wrong-password"))))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("REAUTH_FAILED"));
        mvc.perform(post("/api/v1/auth/reauth").cookie(ownerCookie).with(csrf()).contentType("application/json").content(json.writeValueAsString(Map.of("password",ownerPassword))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.validForSeconds").value(300));

        String pendingToken=Crypto.token();
        db.update("INSERT INTO admin_session(token_hash,id,admin_id,mfa_verified,expires_at,ip_hash,user_agent) VALUES(?,?,?,false,now()+interval '10 minutes',?,'legacy-pending')",Crypto.sha256(pendingToken),UUID.randomUUID(),db.queryForObject("SELECT id FROM admin_user WHERE username='test-owner'",UUID.class),Crypto.sha256("legacy-ip"));
        mvc.perform(get("/api/v1/overview").cookie(new Cookie("AGSESSION",pendingToken))).andExpect(status().isOk());
        String admins=mvc.perform(get("/api/v1/admins").cookie(ownerCookie)).andReturn().getResponse().getContentAsString();
        assertFalse(admins.contains("password_hash"));assertFalse(admins.contains("mfa_secret"));assertFalse(admins.contains("mfa_enabled"));
    }
    Cookie role(String role){
        UUID id=UUID.randomUUID();String token=Crypto.token();
        db.update("INSERT INTO admin_user(id,username,password_hash,role,mfa_enabled) VALUES(?,?,?,?,true)",id,"role-"+id,encoder.encode(Crypto.token()),role);
        db.update("INSERT INTO admin_session(token_hash,id,admin_id,mfa_verified,reauth_at,expires_at,ip_hash,user_agent) VALUES(?,?,?,true,now(),now()+interval '1 hour',?,'test')",Crypto.sha256(token),UUID.randomUUID(),id,Crypto.sha256("test-ip"));
        return new Cookie("AGSESSION",token);
    }
    @Test @Order(3) void leastPrivilegeAndCsrfNegativeCases()throws Exception{
        Cookie auditor=role("Auditor"),operator=role("Operator");String id=UUID.randomUUID().toString();
        mvc.perform(post("/api/v1/backups?nodeId="+id).cookie(auditor).with(csrf()).header("Idempotency-Key",Crypto.token())).andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/mailboxes").cookie(operator).with(csrf()).header("Idempotency-Key",Crypto.token()).contentType("application/json").content(json.writeValueAsString(Map.of("domainId",id,"address","test@example.test","password",Crypto.token(),"quotaBytes",1048576)))).andExpect(status().isForbidden());
        mvc.perform(put("/api/v1/domains/"+id+"/dns/provider").cookie(auditor).with(csrf()).contentType("application/json").content("{\"provider\":\"manual\"}")).andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/auth/logout").cookie(ownerCookie)).andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/auth/logout").cookie(ownerCookie).with(csrf()).header("Origin","https://untrusted.example.test")).andExpect(status().isForbidden());
    }
    @Test @Order(4) void readOnlyNodePreventsMailboxTasksAndNoGuessedWebsiteConnector()throws Exception{
        db.update("UPDATE admin_session SET reauth_at=now()-interval '10 minutes' WHERE token_hash=?",Crypto.sha256(ownerCookie.getValue()));
        UUID guardedDomain=UUID.randomUUID();
        mvc.perform(post("/api/v1/mailboxes").cookie(ownerCookie).with(csrf()).header("Idempotency-Key",Crypto.token()).contentType("application/json").content(json.writeValueAsString(Map.of("domainId",guardedDomain,"address","guard@example.test","password",Crypto.token(),"quotaBytes",1048576))))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("REAUTH_REQUIRED"));
        db.update("UPDATE admin_session SET reauth_at=now() WHERE token_hash=?",Crypto.sha256(ownerCookie.getValue()));
        UUID node=UUID.randomUUID(),domain=UUID.randomUUID();
        db.update("INSERT INTO mail_node(id,name,instance_id) VALUES(?,'Test only','test-instance-01')",node);
        db.update("INSERT INTO mail_domain(id,name,mail_host,public_ipv4,dkim_selector,spf,dmarc,node_id) VALUES(?,'example.test','mail.example.test','192.0.2.1','mail','v=spf1 mx -all','v=DMARC1; p=none;',?)",domain,node);
        db.update("INSERT INTO dns_provider_config(domain_id,provider) VALUES(?,'manual')",domain);
        mvc.perform(post("/api/v1/mailboxes").cookie(ownerCookie).with(csrf()).header("Idempotency-Key",Crypto.token()).contentType("application/json").content(json.writeValueAsString(Map.of("domainId",domain,"address","test@example.test","password",Crypto.token(),"quotaBytes",1048576)))).andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("NODE_READ_ONLY"));
        assertEquals(0,db.queryForObject("SELECT count(*) FROM task",Integer.class));
        mvc.perform(get("/api/v1/website-users").cookie(ownerCookie)).andExpect(jsonPath("$.enabled").value(false));
    }
    @Test @Order(5) void auditAppendOnlyAndSessionRevocation()throws Exception{
        assertThrows(org.springframework.dao.DataAccessException.class,()->db.update("DELETE FROM audit_event"));
        mvc.perform(post("/api/v1/auth/logout").cookie(ownerCookie).with(csrf())).andExpect(status().isOk());
        mvc.perform(get("/api/v1/overview").cookie(ownerCookie)).andExpect(status().isUnauthorized());
    }
    @Test @Order(6) void auditorAndOperatorCannotExecuteDnsPlanActions()throws Exception{
        UUID planId=UUID.randomUUID();
        for(String restrictedRole:List.of("Auditor","Operator")){
            Cookie restricted=role(restrictedRole);
            mvc.perform(post("/api/v1/dns/plans/"+planId+"/apply").cookie(restricted).with(csrf())
                    .contentType("application/json").content(json.writeValueAsString(Map.of("confirmation","APPLY DNS "+planId))))
                    .andExpect(status().isForbidden());
            mvc.perform(post("/api/v1/dns/plans/"+planId+"/rollback").cookie(restricted).with(csrf())
                    .contentType("application/json").content(json.writeValueAsString(Map.of("confirmation","ROLLBACK DNS "+planId))))
                    .andExpect(status().isForbidden());
        }
    }
    @Test @Order(7) void setupRateLimitUsesValidatedProxyClientAddress()throws Exception{
        var body=json.writeValueAsString(Map.of("token","not-valid","username","other-owner","password","LongEnoughForATestPassword123!"));
        for(int i=0;i<8;i++)mvc.perform(post("/api/v1/setup/initialize").with(fromTrustedProxy("198.51.100.71")).with(csrf()).contentType("application/json").content(body)).andExpect(status().isConflict());
        mvc.perform(post("/api/v1/setup/initialize").with(fromTrustedProxy("198.51.100.71")).with(csrf()).contentType("application/json").content(body)).andExpect(status().isTooManyRequests()).andExpect(jsonPath("$.code").value("RATE_LIMITED"));
        mvc.perform(post("/api/v1/setup/initialize").with(fromTrustedProxy("198.51.100.72")).with(csrf()).contentType("application/json").content(body)).andExpect(status().isConflict());
    }
    private static RequestPostProcessor fromTrustedProxy(String clientIp){return request->{request.setRemoteAddr("10.20.0.11");request.addHeader("X-Real-IP",clientIp);return request;};}
}
