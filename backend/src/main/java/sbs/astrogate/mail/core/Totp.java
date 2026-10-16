package sbs.astrogate.mail.core;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** RFC 6238; callers MUST atomically enforce the returned counter > last accepted counter. */
public final class Totp {
    private Totp() {}
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    public static String newSecret() { return encode(Crypto.random(20)); }
    public static String encode(byte[] bytes) {
        StringBuilder out = new StringBuilder(); int bits = 0, buffer = 0;
        for (byte b : bytes) { buffer = (buffer << 8) | (b & 255); bits += 8; while (bits >= 5) { bits -= 5; out.append(ALPHABET.charAt((buffer >> bits) & 31)); } }
        if (bits > 0) out.append(ALPHABET.charAt((buffer << (5 - bits)) & 31));
        return out.toString();
    }
    public static byte[] decode(String value) {
        if (value == null || !value.matches("[A-Z2-7]{16,128}")) throw new IllegalArgumentException("Invalid TOTP secret");
        byte[] out = new byte[value.length() * 5 / 8]; int bits = 0, buffer = 0, pos = 0;
        for (char c : value.toCharArray()) { buffer = (buffer << 5) | ALPHABET.indexOf(c); bits += 5; if (bits >= 8) { bits -= 8; out[pos++] = (byte) (buffer >> bits); } }
        return out;
    }
    public static String code(String secret, long counter) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1"); mac.init(new SecretKeySpec(decode(secret), "HmacSHA1"));
            byte[] digest = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array()); int offset = digest[19] & 15;
            int bin = ((digest[offset] & 127) << 24) | ((digest[offset + 1] & 255) << 16) | ((digest[offset + 2] & 255) << 8) | (digest[offset + 3] & 255);
            return String.format(Locale.ROOT, "%06d", bin % 1000000);
        } catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
    }
    public static long verify(String secret, String value, Instant now, long lastCounter) {
        if (value == null || !value.matches("[0-9]{6}")) return -1;
        long step = now.getEpochSecond() / 30, match = -1;
        for (long i = step - 1; i <= step + 1; i++) if (Crypto.equal(code(secret, i), value) && i > lastCounter) match = i;
        return match;
    }
}
