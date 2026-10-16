package sbs.astrogate.mail.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import sbs.astrogate.mail.api.ApiError;
import static org.junit.jupiter.api.Assertions.*;

class ClientIpResolverTest {
    @Test void ignoresForwardingHeadersFromUntrustedPeers(){
        var request=request("198.51.100.24");request.addHeader("X-Real-IP","203.0.113.8");request.addHeader("X-Forwarded-For","203.0.113.9");
        assertEquals("198.51.100.24",new ClientIpResolver("").resolve(request));
    }

    @Test void readsSingleValidatedAddressOnlyFromConfiguredProxy(){
        var request=request("10.20.0.11");request.addHeader("X-Real-IP","203.0.113.8");request.addHeader("X-Forwarded-For","192.0.2.55");
        assertEquals("203.0.113.8",new ClientIpResolver("10.20.0.0/24").resolve(request));
    }

    @Test void trustedProxyMustProvideOneUnambiguousValidAddress(){
        var resolver=new ClientIpResolver("10.20.0.0/24");
        assertThrows(ApiError.Failure.class,()->resolver.resolve(request("10.20.0.11")));
        var repeated=request("10.20.0.11");repeated.addHeader("X-Real-IP","203.0.113.8");repeated.addHeader("X-Real-IP","203.0.113.9");
        assertThrows(ApiError.Failure.class,()->resolver.resolve(repeated));
        var chain=request("10.20.0.11");chain.addHeader("X-Real-IP","203.0.113.8, 203.0.113.9");
        assertThrows(ApiError.Failure.class,()->resolver.resolve(chain));
        var invalid=request("10.20.0.11");invalid.addHeader("X-Real-IP","trusted.example.test");
        assertThrows(ApiError.Failure.class,()->resolver.resolve(invalid));
    }

    @Test void cidrBoundaryAndAddressFamilyAreEnforced(){
        var resolver=new ClientIpResolver("10.20.0.0/24,2001:db8:1::/48");
        var inside=request("10.20.0.255");inside.addHeader("X-Real-IP","198.51.100.3");assertEquals("198.51.100.3",resolver.resolve(inside));
        var outside=request("10.20.1.0");outside.addHeader("X-Real-IP","203.0.113.4");assertEquals("10.20.1.0",resolver.resolve(outside));
        var v6=request("2001:db8:1::10");v6.addHeader("X-Real-IP","2001:db8:2::1");assertEquals("2001:db8:2:0:0:0:0:1",resolver.resolve(v6));
    }

    @Test void invalidTrustedProxyConfigurationFailsAtStartup(){
        assertThrows(IllegalStateException.class,()->new ClientIpResolver("proxy.internal"));
        assertThrows(IllegalStateException.class,()->new ClientIpResolver("10.20.0.0/33"));
        assertThrows(IllegalStateException.class,()->new ClientIpResolver("0.0.0.0/0"));
    }

    private static MockHttpServletRequest request(String peer){var request=new MockHttpServletRequest();request.setRemoteAddr(peer);return request;}
}
