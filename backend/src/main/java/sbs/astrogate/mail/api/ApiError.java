package sbs.astrogate.mail.api;

import java.util.Map;
import java.util.UUID;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.AccessDeniedException;

@RestControllerAdvice
public class ApiError {
    public static class Failure extends RuntimeException {
        public final int status; public final String code;
        public Failure(int status, String code, String message) { super(message); this.status=status; this.code=code; }
    }
    public static Failure fail(int status, String code, String message) { return new Failure(status, code, message); }
    public static Map<String,Object> body(String code, String message, String id) { return Map.of("code",code,"message",message,"requestId",id); }
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String,Object>> handle(Exception error, HttpServletRequest request) {
        int status=500; String code="INTERNAL_ERROR", message="操作失败，请使用请求编号联系管理员";
        if(error instanceof Failure f) { status=f.status; code=f.code; message=f.getMessage(); }
        else if(error instanceof AccessDeniedException) {status=403;code="FORBIDDEN";message="没有执行该操作的权限";}
        else if(error instanceof IllegalArgumentException) {status=400;code="INVALID_INPUT";message="输入参数不符合约束";}
        else if(error instanceof MethodArgumentNotValidException || error instanceof HttpMessageNotReadableException) {status=400;code="INVALID_INPUT";message="请求字段不正确，未知字段不被接受";}
        else if(error instanceof DataIntegrityViolationException) {status=409;code="CONFLICT";message="对象已存在、状态冲突或仍被引用";}
        String id=(String)request.getAttribute("requestId");
        return ResponseEntity.status(status).body(body(code,message,id==null?UUID.randomUUID().toString():id));
    }
}
