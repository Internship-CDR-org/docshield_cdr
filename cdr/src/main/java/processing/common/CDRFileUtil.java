package processing.common;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Common file operations used by CDR processors for identity-preserving clean outputs. */
public final class CDRFileUtil {
    private static final int BUFFER_SIZE = 8192;

    private CDRFileUtil() { }

    /** Copies a verified-clean input byte-for-byte without parsing/saving it again. */
    public static void copyOriginal(Path input, Path output) throws IOException {
        Path normalizedOutput = output.toAbsolutePath().normalize();
        Path parent = normalizedOutput.getParent();
        if (parent != null) Files.createDirectories(parent);
        Files.copy(input, normalizedOutput, StandardCopyOption.REPLACE_EXISTING);
    }

    /** Calculates SHA-256 without loading the complete file into memory. */
    public static String sha256(Path file) throws IOException {
        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 is unavailable in this Java runtime.", e);
        }
        byte[] buffer = new byte[BUFFER_SIZE];
        try (InputStream in = Files.newInputStream(file)) {
            int read;
            while ((read = in.read(buffer)) != -1) digest.update(buffer, 0, read);
        }
        StringBuilder hex = new StringBuilder(64);
        for (byte b : digest.digest()) hex.append(String.format("%02x", b));
        return hex.toString();
    }
}
