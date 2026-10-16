package sbs.astrogate.mail.api;
import java.util.Map;
import org.springframework.web.bind.annotation.*;
import sbs.astrogate.mail.service.Store;
@RestController
public class LivenessController {
    private final Store store;
    public LivenessController(Store store){this.store=store;}
    @GetMapping("/livez") public Map<String,Object> live(){store.db.queryForObject("SELECT 1",Integer.class);return Map.of("state","ready","version","0.1.0","productionAccepted",false);}
}
