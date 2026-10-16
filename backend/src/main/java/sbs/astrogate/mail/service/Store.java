package sbs.astrogate.mail.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import static sbs.astrogate.mail.api.ApiError.fail;

/** SQL strings are source-controlled constants; no table/column names come from HTTP inputs. */
@Component
public class Store {
    public final JdbcTemplate db; public final ObjectMapper json;
    public Store(JdbcTemplate db, ObjectMapper json) { this.db=db; this.json=json; }
    public Map<String,Object> one(String sql, Object...args) {
        List<Map<String,Object>> rows=db.queryForList(sql,args);
        if(rows.isEmpty()) throw fail(404,"NOT_FOUND","对象不存在");
        return rows.getFirst();
    }
    public String encode(Object value) { try{return json.writeValueAsString(value);}catch(Exception e){throw new IllegalStateException("JSON encoding failed");} }
    public Map<String,Object> map(Object value) {
        if(value instanceof Map<?,?>) return json.convertValue(value,new TypeReference<>(){});
        try{return json.readValue(value.toString(),new TypeReference<>(){});}catch(Exception e){throw new IllegalStateException("Stored JSON invalid");}
    }
    public <T> T decode(Object value, Class<T> type) { try{return json.readValue(value.toString(),type);}catch(Exception e){throw new IllegalStateException("Stored JSON invalid");} }
    public List<Map<String,Object>> maps(Object value) { try{return json.readValue(value.toString(),new TypeReference<>(){});}catch(Exception e){throw new IllegalStateException("Stored JSON invalid");} }
    public String canonical(Object value) {
        try {
            var tree=json.valueToTree(value); return sorted(tree).toString();
        } catch(Exception e) {throw new IllegalArgumentException("Invalid canonical JSON");}
    }
    private com.fasterxml.jackson.databind.JsonNode sorted(com.fasterxml.jackson.databind.JsonNode n) {
        if(n.isObject()) {var result=json.createObjectNode();var keys=new java.util.TreeSet<String>();n.fieldNames().forEachRemaining(keys::add);keys.forEach(k->result.set(k,sorted(n.get(k))));return result;}
        if(n.isArray()) {var result=json.createArrayNode();n.forEach(v->result.add(sorted(v)));return result;} return n;
    }
}
