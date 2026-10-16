package sbs.astrogate.mail.core;

import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Pattern;

/** Deliberately conservative identifiers shared by domain and task validation. */
public final class Checks {
    private Checks() {}
    private static final Pattern LOCAL = Pattern.compile("[a-z0-9][a-z0-9._+-]{0,63}");
    private static final Pattern HOST = Pattern.compile("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?");
    public static String domain(String value) {
        if (value == null || value.length() > 253 || !value.equals(value.strip()) || !value.equals(value.toLowerCase(Locale.ROOT)))
            throw new IllegalArgumentException("域名必须为小写 ASCII / punycode");
        String ascii = IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES);
        if (!ascii.equals(value) || !value.contains(".") || value.endsWith("."))
            throw new IllegalArgumentException("域名格式不正确");
        for (String label : value.split("\\.", -1)) if (!HOST.matcher(label).matches())
            throw new IllegalArgumentException("域名格式不正确");
        return value;
    }
    public static String email(String value) {
        if (value == null || value.length() > 254 || value.indexOf('@') <= 0 || value.indexOf('@') != value.lastIndexOf('@'))
            throw new IllegalArgumentException("只接受一个完整邮箱地址");
        String[] parts = value.split("@", -1);
        if (!LOCAL.matcher(parts[0]).matches() || parts[0].contains("..") || parts[0].endsWith("."))
            throw new IllegalArgumentException("邮箱本地部分格式不正确");
        domain(parts[1]);
        return value;
    }
    public static String mailHost(String host, String domain) {
        domain(host);
        if (!host.endsWith("." + domain) || host.equals("www." + domain))
            throw new IllegalArgumentException("邮件主机必须是专用子域，不能使用网站主机");
        return host;
    }
    public static String ipv4(String value) {
        if (value == null) throw new IllegalArgumentException("需要 IPv4");
        String[] fields = value.split("\\.", -1);
        if (fields.length != 4) throw new IllegalArgumentException("IPv4 格式不正确");
        for (String part : fields) {
            if (!part.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(part) > 255)
                throw new IllegalArgumentException("IPv4 格式不正确");
        }
        return value;
    }
    public static String password(String value) {
        if (value == null || value.length() < 14 || value.getBytes(StandardCharsets.UTF_8).length > 72 || value.chars().anyMatch(Character::isISOControl))
            throw new IllegalArgumentException("密码需至少 14 个字符，且 UTF-8 长度不超过 72 字节");
        return value;
    }
    public static String uuid(String value) {
        if (value == null || !UUID.fromString(value).toString().equals(value))
            throw new IllegalArgumentException("需要标准 UUID");
        return value;
    }
    public static String text(String value, int max) {
        if (value == null || value.isBlank() || value.length() > max || value.chars().anyMatch(Character::isISOControl))
            throw new IllegalArgumentException("字段为空、过长或含控制字符");
        return value;
    }
    public static long quota(long value) {
        if (value < 1048576L || value > 1099511627776L) throw new IllegalArgumentException("配额范围为 1 MiB 至 1 TiB");
        return value;
    }
    public static String zone(String value) {
        if (value == null || !value.matches("[a-f0-9]{32}")) throw new IllegalArgumentException("Zone ID 格式不正确");
        return value;
    }
}
