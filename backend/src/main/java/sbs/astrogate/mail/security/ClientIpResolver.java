package sbs.astrogate.mail.security;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import static sbs.astrogate.mail.api.ApiError.fail;

/** Resolves the peer address unless that peer is an explicitly trusted proxy. */
@Component
public final class ClientIpResolver {
    private static final Pattern IPV4=Pattern.compile("[0-9]{1,3}(\\.[0-9]{1,3}){3}");
    private static final Pattern IPV6=Pattern.compile("[0-9a-fA-F:.]+");
    private final List<Subnet> trusted;

    public ClientIpResolver(@Value("${admin.trusted-proxy-cidrs:}") String cidrs) {
        trusted=new ArrayList<>();
        for(String value:cidrs.split(","))if(!value.isBlank())trusted.add(Subnet.parse(value.strip()));
    }

    public String resolve(HttpServletRequest request) {
        String peer=request.getRemoteAddr();
        byte[] peerBytes=parseAddress(peer);
        if(trusted.stream().noneMatch(subnet->subnet.contains(peerBytes)))return format(peerBytes);

        var headers=request.getHeaders("X-Real-IP");
        if(!headers.hasMoreElements())throw fail(400,"CLIENT_IP_UNAVAILABLE","可信代理未提供客户端地址");
        String value=headers.nextElement();
        if(headers.hasMoreElements())throw fail(400,"CLIENT_IP_UNAVAILABLE","可信代理客户端地址格式无效");
        return format(parseAddress(value));
    }

    public static String normalize(String value){return format(parseAddress(value));}

    private static byte[] parseAddress(String value) {
        if(value==null)throw fail(400,"CLIENT_IP_UNAVAILABLE","客户端地址格式无效");
        String ip=value.strip();
        if(!IPV4.matcher(ip).matches()&&!IPV6.matcher(ip).matches())throw fail(400,"CLIENT_IP_UNAVAILABLE","客户端地址格式无效");
        if(ip.indexOf(':')<0){
            String[] octets=ip.split("\\.");byte[] bytes=new byte[4];
            for(int i=0;i<4;i++){int part;try{part=Integer.parseInt(octets[i]);}catch(NumberFormatException e){throw fail(400,"CLIENT_IP_UNAVAILABLE","客户端地址格式无效");}if(part>255)throw fail(400,"CLIENT_IP_UNAVAILABLE","客户端地址格式无效");bytes[i]=(byte)part;}
            return bytes;
        }
        try{return InetAddress.getByName(ip).getAddress();}
        catch(UnknownHostException e){throw fail(400,"CLIENT_IP_UNAVAILABLE","客户端地址格式无效");}
    }

    private static String format(byte[] address) {
        try{return InetAddress.getByAddress(address).getHostAddress();}
        catch(UnknownHostException impossible){throw new IllegalStateException(impossible);}
    }

    private record Subnet(byte[] network,int prefix) {
        static Subnet parse(String value) {
            String[] parts=value.split("/",-1);
            if(parts.length!=2)throw new IllegalStateException("ADMIN_TRUSTED_PROXY_CIDRS entries require a CIDR prefix");
            byte[] address=parseConfigAddress(parts[0]);int max=address.length*8;int prefix;
            try{prefix=Integer.parseInt(parts[1]);}catch(NumberFormatException e){throw new IllegalStateException("ADMIN_TRUSTED_PROXY_CIDRS contains an invalid prefix");}
            if(prefix<1||prefix>max)throw new IllegalStateException("ADMIN_TRUSTED_PROXY_CIDRS contains an invalid or overly broad prefix");
            return new Subnet(address,prefix);
        }
        boolean contains(byte[] address) {
            if(address.length!=network.length)return false;
            int fullBytes=prefix/8,remainingBits=prefix%8;
            for(int i=0;i<fullBytes;i++)if(address[i]!=network[i])return false;
            if(remainingBits==0)return true;
            int mask=0xff<<(8-remainingBits);
            return (address[fullBytes]&mask)==(network[fullBytes]&mask);
        }
        private static byte[] parseConfigAddress(String value) {
            try{return parseAddress(value);}
            catch(RuntimeException e){throw new IllegalStateException("ADMIN_TRUSTED_PROXY_CIDRS contains an invalid IP address");}
        }
    }
}
