package sbs.astrogate.mail.core;
import java.io.IOException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.postgresql.util.PGobject;
import org.springframework.context.annotation.*;
@Configuration
public class JsonConfig {
    @Bean public com.fasterxml.jackson.databind.Module postgresJsonModule(){
        SimpleModule module=new SimpleModule();
        module.addSerializer(PGobject.class,new JsonSerializer<PGobject>(){
            @Override public void serialize(PGobject value,JsonGenerator output,SerializerProvider provider)throws IOException{
                if(value.getValue()==null){output.writeNull();return;}
                if("json".equals(value.getType())||"jsonb".equals(value.getType())){
                    JsonNode tree=((ObjectMapper)output.getCodec()).readTree(value.getValue());output.writeTree(tree);
                }else output.writeString(value.getValue());
            }
        });return module;
    }
}
