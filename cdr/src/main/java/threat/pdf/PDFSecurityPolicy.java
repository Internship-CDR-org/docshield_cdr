package threat.pdf;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** Central safety policy for untrusted PDF processing. */
public final class PDFSecurityPolicy {
    private PDFSecurityPolicy() {}

    public static final long MAX_INPUT_BYTES = 200L * 1024L * 1024L;
    public static final long MAX_EMBEDDED_PAYLOAD_BYTES = 64L * 1024L * 1024L;
    public static final int MAX_EMBEDDED_PAYLOADS = 256;
    public static final int MAX_COS_OBJECTS = 200_000;
    public static final int MAX_PAGES = 10_000;
    public static final int MAX_URI_DECODE_ROUNDS = 3;
    /** Maximum recursive COS graph depth before inspection fails closed. */
    public static final int MAX_COS_GRAPH_DEPTH = 256;

    public static boolean isDangerousUri(String uri) {
        String normalized = normalizeUriForPolicy(uri);
        if (normalized == null || normalized.isEmpty()) return false;
        int colon = normalized.indexOf(':');
        if (colon <= 0) return false;
        String scheme = normalized.substring(0, colon).toLowerCase(Locale.ROOT);
        return scheme.equals("javascript") || scheme.equals("vbscript")
                || scheme.equals("file") || scheme.equals("data")
                || scheme.equals("shell") || scheme.equals("mk")
                || scheme.equals("acrobat") || scheme.startsWith("ms-");
    }

    public static String normalizeUriForPolicy(String uri) {
        if (uri == null) return null;
        String value = uri;
        for (int round = 0; round < MAX_URI_DECODE_ROUNDS; round++) {
            value = stripLeadingControls(value);
            String decoded;
            try {
                decoded = URLDecoder.decode(value, StandardCharsets.UTF_8);
            } catch (IllegalArgumentException ex) {
                break;
            }
            if (decoded.equals(value)) break;
            value = decoded;
        }
        return stripLeadingControls(value).toLowerCase(Locale.ROOT);
    }

    private static String stripLeadingControls(String value) {
        int start = 0;
        while (start < value.length()) {
            char c = value.charAt(start);
            if (Character.isWhitespace(c) || c < 0x20 || c == 0x7f) start++;
            else break;
        }
        return value.substring(start);
    }
}
