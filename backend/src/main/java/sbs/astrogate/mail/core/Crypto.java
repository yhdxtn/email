package sbs.astrogate.mail.core;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Versioned AES-256-GCM envelopes with purpose-bound associated data. */
public final class Crypto {
    private static final SecureRandom RANDOM = new SecureRandom();
    private final byte[] key;
    public Crypto(byte[] key) {
        if (key.length != 32) throw new IllegalArgumentException("Master key must be 32 bytes");
        this.key = key.clone();
    }
    public static byte[] random(int size) { byte[] b = new byte[size]; RANDOM.nextBytes(b); return b; }
    public static String token() { return Base64.getUrlEncoder().withoutPadding().encodeToString(random(32)); }
    public static String sha256(String text) { return HexFormat.of().formatHex(hash(text.getBytes(StandardCharsets.UTF_8))); }
    public static byte[] hash(byte[] input) {
        try { return MessageDigest.getInstance("SHA-256").digest(input); }
        catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
    }
    public static String hmac(byte[] key, byte[] text) {
        try { Mac m = Mac.getInstance("HmacSHA256"); m.init(new SecretKeySpec(key, "HmacSHA256")); return HexFormat.of().formatHex(m.doFinal(text)); }
        catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
    }
    public String fingerprint(String text) { return hmac(key, ("fingerprint-v1\n" + text).getBytes(StandardCharsets.UTF_8)); }
    public static boolean equal(String a, String b) {
        return a != null && b != null && MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
    public String seal(String purpose, String value) {
        try {
            byte[] iv = random(12);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            cipher.updateAAD(("astrogate:v1:" + purpose).getBytes(StandardCharsets.UTF_8));
            byte[] data = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
            return "v1:k1:" + Base64.getEncoder().encodeToString(ByteBuffer.allocate(iv.length + data.length).put(iv).put(data).array());
        } catch (GeneralSecurityException e) { throw new IllegalStateException("Encryption failed"); }
    }
    public String open(String purpose, String envelope) {
        try {
            if (envelope == null || !envelope.startsWith("v1:k1:")) throw new IllegalArgumentException("Invalid envelope version");
            byte[] raw = Base64.getDecoder().decode(envelope.substring(6));
            if (raw.length < 28) throw new IllegalArgumentException("Invalid envelope");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, Arrays.copyOf(raw, 12)));
            cipher.updateAAD(("astrogate:v1:" + purpose).getBytes(StandardCharsets.UTF_8));
            return new String(cipher.doFinal(Arrays.copyOfRange(raw, 12, raw.length)), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) { throw new IllegalArgumentException("Secret cannot be authenticated"); }
    }
}
